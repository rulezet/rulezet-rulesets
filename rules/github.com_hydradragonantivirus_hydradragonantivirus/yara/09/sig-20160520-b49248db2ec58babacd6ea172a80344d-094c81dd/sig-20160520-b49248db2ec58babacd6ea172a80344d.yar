rule sig_20160520_b49248db2ec58babacd6ea172a80344d {
  meta:
    description = "datamaliciousorder - file 20160520_b49248db2ec58babacd6ea172a80344d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29a5d7ad2cc6eb5302864788824b4078619a2d34302e692fa610517d533332fb"

  strings:
    $s1  = "function IWetVoeh(pMHZB) {var ImcRTRUX=VTiuCYAUTSKGjrC[2];for(var MUGde=0;MUGde<pMHZB;MUGde++){tQWoO+=ImcRTRUX.charAt(Math.floor" ascii
    $s2  = "function IWetVoeh(pMHZB) {var ImcRTRUX=VTiuCYAUTSKGjrC[2];for(var MUGde=0;MUGde<pMHZB;MUGde++){tQWoO+=ImcRTRUX.charAt(Math.floor" ascii
    $s3  = "WcNrBA.length;ccePLple++) {JAdibev+=dDLHq[WcNrBA[ccePLple]];}return JAdibev.substring(3,JAdibev.length);}" fullword ascii
    $s4  = "function AkbIKDPEL(CNoKrNMlJ,jusPRmM,tdNvILTa){" fullword ascii
    $s5  = "function acLA(hKWNFN,mynjksw){xVGY = VTiuCYAUTSKGjrC[11].split(VTiuCYAUTSKGjrC[12]);mynjksw.open(xVGY[0]+xVGY[2]+xVGY[3], hKWNFN" ascii
    $s6  = "function LLHPh(PJIxMc){return new ActiveXObject(PJIxMc);}" fullword ascii
    $s7  = "try{AkbIKDPEL(FHuWe[ZIWj], OlsQXeI() + VTiuCYAUTSKGjrC[9], 1)}catch(e){}; " fullword ascii
    $s8  = "function ByhWX(vBiPYQQw,GffIs,ZMSFEXSrxy){vBiPYQQw.open();vBiPYQQw.type = 1;vBiPYQQw.write(GffIs);vBiPYQQw.position = 0;vBiPYQQw" ascii
    $s9  = "function OlsQXeI() {var nmlL=100000;var uosTJg = 100;return Math.random()*(nmlL-uosTJg)+uosTJg;}" fullword ascii
    $s10 = ", false);mynjksw.send();}" fullword ascii
    $s11 = "(Math.random()*ImcRTRUX.length));}return tQWoO;}" fullword ascii
    $s12 = "function IenXO(PhebHErh,WcNrBA,YqNxeqzQH){dDLHq=PhebHErh.split(YqNxeqzQH);JAdibev = VTiuCYAUTSKGjrC[13];for(ccePLple=0;ccePLple<" ascii
    $s13 = "function usUjde(PJIxMc){return PJIxMc.ExpandEnvironmentStrings(VTiuCYAUTSKGjrC[10])}" fullword ascii
    $s14 = "function acLA(hKWNFN,mynjksw){xVGY = VTiuCYAUTSKGjrC[11].split(VTiuCYAUTSKGjrC[12]);mynjksw.open(xVGY[0]+xVGY[2]+xVGY[3], hKWNFN" ascii
    $s15 = "function ByhWX(vBiPYQQw,GffIs,ZMSFEXSrxy){vBiPYQQw.open();vBiPYQQw.type = 1;vBiPYQQw.write(GffIs);vBiPYQQw.position = 0;vBiPYQQw" ascii
    $s16 = "function IenXO(PhebHErh,WcNrBA,YqNxeqzQH){dDLHq=PhebHErh.split(YqNxeqzQH);JAdibev = VTiuCYAUTSKGjrC[13];for(ccePLple=0;ccePLple<" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}