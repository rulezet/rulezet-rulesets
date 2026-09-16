rule sig_20160307_33444f74c6fcc3dc3011c3fc52a6844d {
  meta:
    description = "datamaliciousorder - file 20160307_33444f74c6fcc3dc3011c3fc52a6844d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a097c6743c00df9209eea61869fee3b75217279a3fa688563fb1387a57f130c2"

  strings:
    $s1  = "return vPeVbqy[0] + vPeVbqy[2] + vPeVbqy[4] + \".F\" + vPeVbqy[7] + vPeVbqy[9] + vPeVbqy[12] + vPeVbqy[14];" fullword ascii
    $s2  = "var oa = true  , jlRX = cUq[7] + cUq[9] + cUq[11];" fullword ascii
    $s3  = "var cUq = (\"2.XMLHTTP UxqNbWS EEsYl XML ream St mXEDZuxT AD XRUjEbL O jSwh D\").split(\" \");" fullword ascii
    $s4  = "var vPeVbqy = \"Sc gBSiiFO r HtpNEaKsZ ipting wmtQVRo wMo ile qPzXyjZHVBKciC System ef AhRpS Obj ojQTAF ect HmEQOTw\".split(\" " ascii
    $s5  = "ekOHz.open(sURee,kkMsY,false);" fullword ascii
    $s6  = "function QKuwdHE(kqKi) {" fullword ascii
    $s7  = "function hAXO(udgjF) {" fullword ascii
    $s8  = "return new ActiveXObject(sCdKlD);" fullword ascii
    $s9  = "return Dk.ExpandEnvironmentStrings(yAzml[6]+yAzml[7]+yAzml[8]);" fullword ascii
    $s10 = "function ltcVy(sCdKlD) {" fullword ascii
    $s11 = "function XrLtdfO(vhQp) {" fullword ascii
    $s12 = "return vhQp.responseBody;" fullword ascii
    $s13 = "return WsE.size;" fullword ascii
    $s14 = "JNT = h; break; " fullword ascii
    $s15 = "function WcCI(uKEeJ) {" fullword ascii
    $s16 = "function ZCSN(JodEX) {" fullword ascii
    $s17 = "if (((new Date())>0,7767162888)) {" fullword ascii
    $s18 = "function lCXb(jsUCZ) {" fullword ascii
    $s19 = "function FqYI(SytRh,jyher) {" fullword ascii
    $s20 = "function lzZwmsjgH(VofXQtBbRDC) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}