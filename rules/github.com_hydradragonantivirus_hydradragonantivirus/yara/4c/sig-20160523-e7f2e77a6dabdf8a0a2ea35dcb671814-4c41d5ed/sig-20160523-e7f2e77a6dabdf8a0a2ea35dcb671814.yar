rule sig_20160523_e7f2e77a6dabdf8a0a2ea35dcb671814 {
  meta:
    description = "datamaliciousorder - file 20160523_e7f2e77a6dabdf8a0a2ea35dcb671814.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83c37b5c28e4c27a4fdaf38ed30fc059fb720cb84b54e387066e83ce0b4fc95a"

  strings:
    $s1  = "function SCIfYxqK(CJOLt) {var XkEnvFUM=AJkAeKlzacxNSvIc[13];for(var VjNXW=0;VjNXW<CJOLt;VjNXW++){IPlJW+=XkEnvFUM.charAt(Math.flo" ascii
    $s2  = "function qWyhvjuIeL(RXwfmAMG,MVTYQlHKsFzP) {RXwfmAMG.Run(MVTYQlHKsFzP, 0x1, 0x0);}" fullword ascii
    $s3  = "function eHhryepZEZ() {return/*jiJORzUzjCeaDCiNYLNjvmORUADzsykKZQXyoNSCrxZSOvkDBXBtmDSBlJpbYObOTOvUxgOZBJONMcKCRiLocSzyfmNJnMScz" ascii
    $s4  = "function SCIfYxqK(CJOLt) {var XkEnvFUM=AJkAeKlzacxNSvIc[13];for(var VjNXW=0;VjNXW<CJOLt;VjNXW++){IPlJW+=XkEnvFUM.charAt(Math.flo" ascii
    $s5  = "function ZkUp(LYUXqZ) {LYUXqZ.open();}" fullword ascii
    $s6  = "function InyAFzAKmXqJN() {eHhryepZEZ().Sleep(2300076-948);}" fullword ascii
    $s7  = "function jLhhBhX(inqj,FjxSb) {inqj.write(FjxSb);}" fullword ascii
    $s8  = "function kmZex(MrKnTQYR,VnouP,NPkSsaHXaJ){ZkUp(MrKnTQYR);LpLqqjjy(MrKnTQYR);jLhhBhX(MrKnTQYR,VnouP);BQDUBxcjn(MrKnTQYR);ExfB(MrK" ascii
    $s9  = "ay, false);wURLlHf.send();}" fullword ascii
    $s10 = "function eHhryepZEZ() {return/*jiJORzUzjCeaDCiNYLNjvmORUADzsykKZQXyoNSCrxZSOvkDBXBtmDSBlJpbYObOTOvUxgOZBJONMcKCRiLocSzyfmNJnMScz" ascii
    $s11 = "function zMSqsfP() {var cevb=100000;var jhCnyR = 100;return ZzYOGLD()*(cevb-jhCnyR)+jhCnyR;}" fullword ascii
    $s12 = "function YgCo(HWdFay,wURLlHf){FNWb = AJkAeKlzacxNSvIc[10].split(AJkAeKlzacxNSvIc[11]);wURLlHf.open(FNWb[0]+FNWb[2]+FNWb[3], HWdF" ascii
    $s13 = "function BQDUBxcjn(hHUanN) {var foegYRrkbl=[];hHUanN.position=foegYRrkbl.length*(5645265-954);}" fullword ascii
    $s14 = "function kSvVrtP(ajVHe) {ajVHe.close();}" fullword ascii
    $s15 = "function ErCHs(TZBLBokj,NTrRkv,LGKTBDlTK){zkiER=TZBLBokj.split(LGKTBDlTK);zXORZvA = AJkAeKlzacxNSvIc[12];for(IKtNKpTM=0;IKtNKpTM" ascii
    $s16 = "function kmZex(MrKnTQYR,VnouP,NPkSsaHXaJ){ZkUp(MrKnTQYR);LpLqqjjy(MrKnTQYR);jLhhBhX(MrKnTQYR,VnouP);BQDUBxcjn(MrKnTQYR);ExfB(MrK" ascii
    $s17 = "function ZzYOGLD(){return Math.random();}" fullword ascii
    $s18 = "or(Math.random()*XkEnvFUM.length));}return IPlJW;}" fullword ascii
    $s19 = "function LpLqqjjy(SZXRaVGCp) {SZXRaVGCp.type=1;}" fullword ascii
    $s20 = "function YgCo(HWdFay,wURLlHf){FNWb = AJkAeKlzacxNSvIc[10].split(AJkAeKlzacxNSvIc[11]);wURLlHf.open(FNWb[0]+FNWb[2]+FNWb[3], HWdF" ascii

  condition:
    uint16(0) == 0x0127 and
    8 of them
}