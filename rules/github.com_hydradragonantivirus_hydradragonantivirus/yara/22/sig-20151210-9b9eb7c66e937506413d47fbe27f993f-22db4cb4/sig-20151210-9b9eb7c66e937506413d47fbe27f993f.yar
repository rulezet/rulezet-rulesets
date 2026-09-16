rule sig_20151210_9b9eb7c66e937506413d47fbe27f993f {
  meta:
    description = "datamaliciousorder - file 20151210_9b9eb7c66e937506413d47fbe27f993f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d020c68d48675ca7887bb55cabed8a2b004cc9fcf4ad28dd3020a736eec3f215"

  strings:
    $s1  = "function aVuaMvf(TmBtsAdqdMtfvsenKtdSElslzpWtnWfPusNk) {return !isNaN(parseFloat(TmBtsAdqdMtfvsenKtdSElslzpWtnWfPusNk)) && isFin" ascii
    $s2  = "function aVuaMvf(TmBtsAdqdMtfvsenKtdSElslzpWtnWfPusNk) {return !isNaN(parseFloat(TmBtsAdqdMtfvsenKtdSElslzpWtnWfPusNk)) && isFin" ascii
    $s3  = "JigEfcE=(-118+118)/796;while(true){if(JigEfcE>=(18036+12)/141){break;}rcPKkhRpHuehq[JigEfcE]=String.fromCharCode(JigEfcE);JigEfc" ascii
    $s4  = " return xjRZsERlDxR}" fullword ascii
    $s5  = "function bdxDqIDRqOqxckWSYVTCDTVlwRACLuaydnNvGXxPEFZcVDVufHVGYz(vAAXiKBNNHDPz,lffWhCFPbLgkhN){ return rcPKkhRpHuehq[TgTxL(vAAXiK" ascii
    $s6  = "function TgTxL(OiCqeNpMWqt,EYVujaKrmsclj,ZfWAkTwD){KIXm=parseInt(OiCqeNpMWqt,EYVujaKrmsclj);EmBMk=KIXm.toString(ZfWAkTwD);return" ascii
    $s7  = " EmBMk;}function gqRobJphjKoeFsS(VUwutKUXxxIBGaREj){eval(VUwutKUXxxIBGaREj)}" fullword ascii
    $s8  = "function oSqiLbDlpcqSMPBeb(HizYL){xjRZsERlDxR= '';for(zZhbnEPOPuf=(-2+2)/841; zZhbnEPOPuf < (-245+345)/50; zZhbnEPOPuf++) {LzrJZ" ascii
    $s9  = "function oSqiLbDlpcqSMPBeb(HizYL){xjRZsERlDxR= '';for(zZhbnEPOPuf=(-2+2)/841; zZhbnEPOPuf < (-245+345)/50; zZhbnEPOPuf++) {LzrJZ" ascii
    $s10 = "function bdxDqIDRqOqxckWSYVTCDTVlwRACLuaydnNvGXxPEFZcVDVufHVGYz(vAAXiKBNNHDPz,lffWhCFPbLgkhN){ return rcPKkhRpHuehq[TgTxL(vAAXiK" ascii
    $s11 = "function TgTxL(OiCqeNpMWqt,EYVujaKrmsclj,ZfWAkTwD){KIXm=parseInt(OiCqeNpMWqt,EYVujaKrmsclj);EmBMk=KIXm.toString(ZfWAkTwD);return" ascii
    $s12 = "JigEfcE=(-118+118)/796;while(true){if(JigEfcE>=(18036+12)/141){break;}rcPKkhRpHuehq[JigEfcE]=String.fromCharCode(JigEfcE);JigEfc" ascii
    $s13 = "function fpRohbjBJMn(qnWuBAbS,XJSavP){return qnWuBAbS.split(XJSavP)}" fullword ascii
    $s14 = "oQNO[zZhbnEPOPuf]=(-792+792)/156; while(true) { if(LzrJZoQNO[zZhbnEPOPuf] > HizYL[zZhbnEPOPuf].length-(401+128)/529) { break; } " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}