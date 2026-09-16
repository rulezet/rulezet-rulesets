rule sig_20160523_5491283ef404eb6b9a0ee45a7ebe6877 {
  meta:
    description = "datamaliciousorder - file 20160523_5491283ef404eb6b9a0ee45a7ebe6877.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe3767c65100bdd55e5ea8e863d740ae256a578141b17a9ec30d2163439446ca"

  strings:
    $s1  = "function kuoefQDUeQ() {return/*FeUONMJKjBATtqgtoVsqtmrijvPbccRwsqnxXaaApqLRFiZYanhrMytUiLixmdonKXNAJJiCoMmmyhuukBhDJbhucHzwsvmaR" ascii
    $s2  = "function xtVcUVPOhZ(rjNGMsbU,SoLzMvnCuyDj) {rjNGMsbU.Run(SoLzMvnCuyDj, 0x1, 0x0);}" fullword ascii
    $s3  = "function aJVdTUDP(xIkuc) {var HiBtabIS=bUVcbUx[13];for(var PHNBn=0;PHNBn<xIkuc;PHNBn++){vdcZJ+=HiBtabIS.charAt(Math.floor(Math.r" ascii
    $s4  = "function aJVdTUDP(xIkuc) {var HiBtabIS=bUVcbUx[13];for(var PHNBn=0;PHNBn<xIkuc;PHNBn++){vdcZJ+=HiBtabIS.charAt(Math.floor(Math.r" ascii
    $s5  = "function AypVx(XMSyfouf,FBgCmd,TiUltinsz){Aqydo=XMSyfouf.split(TiUltinsz);WOcxrQh = bUVcbUx[12];for(DiMRHxoH=0;DiMRHxoH<FBgCmd.l" ascii
    $s6  = "function kuoefQDUeQ() {return/*FeUONMJKjBATtqgtoVsqtmrijvPbccRwsqnxXaaApqLRFiZYanhrMytUiLixmdonKXNAJJiCoMmmyhuukBhDJbhucHzwsvmaR" ascii
    $s7  = "ength;DiMRHxoH++) {WOcxrQh+=Aqydo[FBgCmd[DiMRHxoH]];}return WOcxrQh.substring(3,WOcxrQh.length);}" fullword ascii
    $s8  = "function AypVx(XMSyfouf,FBgCmd,TiUltinsz){Aqydo=XMSyfouf.split(TiUltinsz);WOcxrQh = bUVcbUx[12];for(DiMRHxoH=0;DiMRHxoH<FBgCmd.l" ascii
    $s9  = "function UJAjiw(IfQVAd){return IfQVAd.ExpandEnvironmentStrings(bUVcbUx[9])}" fullword ascii
    $s10 = "function mwFl(wLCYxUb,jrLRhkD) {wLCYxUb.saveToFile(jrLRhkD, 2);}" fullword ascii
    $s11 = "function RqRlW(IfQVAd){return new ActiveXObject(IfQVAd);}" fullword ascii
    $s12 = "function JKJY(PFZOSP,FFXsCRM){mcvq = bUVcbUx[10].split(bUVcbUx[11]);FFXsCRM.open(mcvq[0]+mcvq[2]+mcvq[3], PFZOSP, false);FFXsCRM" ascii
    $s13 = "function okIcModzt(gJXGFW) {var MuiHCXHNIk=[];gJXGFW.position=MuiHCXHNIk.length*(3200808-736);}" fullword ascii
    $s14 = "function MYgPO(eeVLSgJr,LcEPZ,TrEOlPZfSz){olAy(eeVLSgJr);TyOOKscL(eeVLSgJr);eUjotSw(eeVLSgJr,LcEPZ);okIcModzt(eeVLSgJr);mwFl(eeV" ascii
    $s15 = "function MYgPO(eeVLSgJr,LcEPZ,TrEOlPZfSz){olAy(eeVLSgJr);TyOOKscL(eeVLSgJr);eUjotSw(eeVLSgJr,LcEPZ);okIcModzt(eeVLSgJr);mwFl(eeV" ascii
    $s16 = "function olAy(nnvWEj) {nnvWEj.open();}" fullword ascii
    $s17 = "if(SAqM>ZzpYb.length) break;" fullword ascii
    $s18 = "function VzNxUyl(){return Math.random();}" fullword ascii
    $s19 = "function SojRwre() {var oDhh=100000;var eTYTge = 100;return VzNxUyl()*(oDhh-eTYTge)+eTYTge;}" fullword ascii
    $s20 = "andom()*HiBtabIS.length));}return vdcZJ;}" fullword ascii

  condition:
    uint16(0) == 0x0227 and
    8 of them
}