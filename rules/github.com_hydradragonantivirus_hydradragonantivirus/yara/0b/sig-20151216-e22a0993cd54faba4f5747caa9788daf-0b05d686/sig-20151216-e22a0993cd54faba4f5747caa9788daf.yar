rule sig_20151216_e22a0993cd54faba4f5747caa9788daf {
  meta:
    description = "datamaliciousorder - file 20151216_e22a0993cd54faba4f5747caa9788daf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7239280c2e524beb86d36d57b5d6b97af7f13a588bcf221e245d6d0908ac0fbb"

  strings:
    $s1  = "h.pow(Math.cos(253), 2) - 1)); while(true) { if(qnmQNwoVV[WgBiFXjBGhl] > UwhXZ[WgBiFXjBGhl].length-(513+425)/938) { break; } if " ascii
    $s2  = "w(Math.cos(786), 2) - 1)));} qnmQNwoVV[WgBiFXjBGhl]++;}WgBiFXjBGhl++;} return pWxpUScgacY}" fullword ascii
    $s3  = "function VdAVLQmZAcRwtRJEA(UwhXZ){pWxpUScgacY= '';WgBiFXjBGhl=Math.round((Math.pow(Math.sin(926), 2) + Math.pow(Math.cos(926), 2" ascii
    $s4  = ") - 1));while(true){if (WgBiFXjBGhl >= (617+259)/146){break;}qnmQNwoVV[WgBiFXjBGhl]=Math.round((Math.pow(Math.sin(253), 2) + Mat" ascii
    $s5  = "function VdAVLQmZAcRwtRJEA(UwhXZ){pWxpUScgacY= '';WgBiFXjBGhl=Math.round((Math.pow(Math.sin(926), 2) + Math.pow(Math.cos(926), 2" ascii
    $s6  = "function mwafXZm(vonLPeehsKaabfPCnTIRlHnnwBTYTSUNKOIl) {return !wMPVTiDpfha(xvBtdXQGUumrvwo(vonLPeehsKaabfPCnTIRlHnnwBTYTSUNKOIl" ascii
    $s7  = "C);return BhTJA;}" fullword ascii
    $s8  = "function RaVOs(MMgVpwyirov,ssncnOnATLleh,KtiytNiC){dUUQ=CWbEfrXFvikqkAmOK(MMgVpwyirov,ssncnOnATLleh);BhTJA=dUUQ.toString(KtiytNi" ascii
    $s9  = "function G(QtLfRicxCXfn,gVWEYlBOHuQtgV){QtLfRicxCXfn.push(gVWEYlBOHuQtgV);}" fullword ascii
    $s10 = "function VQtAvtqBstvxgThZKKMxNJDKeajrEWfMdhXzJnSOxveaTBVBtbnXaG(lveptPpwmiDUa,aWPfOVZZFWSODg){ return aTwoQNo[AEskqhuI[RaVOs(lve" ascii
    $s11 = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii
    $s12 = "function wMPVTiDpfha(XELtVFHDOLgxVV) {return isNaN(XELtVFHDOLgxVV);}" fullword ascii
    $s13 = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii
    $s14 = "function w(SObZbYXGBYlgoS,JyAiRUXYAgzcT,NHyfOSNAdUo) {SObZbYXGBYlgoS[JyAiRUXYAgzcT]=NHyfOSNAdUo;}" fullword ascii
    $s15 = "function RaVOs(MMgVpwyirov,ssncnOnATLleh,KtiytNiC){dUUQ=CWbEfrXFvikqkAmOK(MMgVpwyirov,ssncnOnATLleh);BhTJA=dUUQ.toString(KtiytNi" ascii
    $s16 = "function FlZUVFWpQCjS(oyupHHZLmtxsn) {return isFinite(oyupHHZLmtxsn);}" fullword ascii
    $s17 = "function VQtAvtqBstvxgThZKKMxNJDKeajrEWfMdhXzJnSOxveaTBVBtbnXaG(lveptPpwmiDUa,aWPfOVZZFWSODg){ return aTwoQNo[AEskqhuI[RaVOs(lve" ascii
    $s18 = "function xvBtdXQGUumrvwo(zCxJNDHnXVpcxvLqUdD) {return parseFloat(zCxJNDHnXVpcxvLqUdD);}" fullword ascii
    $s19 = "function CWbEfrXFvikqkAmOK(KXoBuuZWcu,tGAjeWrkvV) {return parseInt(KXoBuuZWcu,tGAjeWrkvV);}" fullword ascii
    $s20 = "function mwafXZm(vonLPeehsKaabfPCnTIRlHnnwBTYTSUNKOIl) {return !wMPVTiDpfha(xvBtdXQGUumrvwo(vonLPeehsKaabfPCnTIRlHnnwBTYTSUNKOIl" ascii

  condition:
    uint16(0) == 0x4541 and
    8 of them
}