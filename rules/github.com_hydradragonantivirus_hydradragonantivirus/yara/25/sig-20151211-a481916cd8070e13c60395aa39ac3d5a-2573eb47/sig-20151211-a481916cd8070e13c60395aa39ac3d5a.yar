rule sig_20151211_a481916cd8070e13c60395aa39ac3d5a {
  meta:
    description = "datamaliciousorder - file 20151211_a481916cd8070e13c60395aa39ac3d5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "244ecba18b9f410e31691f89255fab52d5939f98d7ff689a925be662cb9a0d0b"

  strings:
    $s1  = "function NCYXavf(hBKSWLHYuDyJihOQQkAXbDRQQmtqIGUzcDDv) {return !isNaN(parseFloat(hBKSWLHYuDyJihOQQkAXbDRQQmtqIGUzcDDv)) && isFin" ascii
    $s2  = "function NCYXavf(hBKSWLHYuDyJihOQQkAXbDRQQmtqIGUzcDDv) {return !isNaN(parseFloat(hBKSWLHYuDyJihOQQkAXbDRQQmtqIGUzcDDv)) && isFin" ascii
    $s3  = "function JMudolZfuvWuFuJES(bPeNd){XoTgCyXTcKz= '';nVGPPwgDWTK=(-401+401)/474; while(true){if(nVGPPwgDWTK >= (658+978)/818)break;" ascii
    $s4  = "function bZIfrnkPxOZwPudgnSSiSQoSblyEVPfIAbjPQYBJNyjYupMfcQyHXG(CKxbPahQBdbFK,LZkpwqcpFfuxCs){ return OnHmk[SzoDx(CKxbPahQBdbFK[" ascii
    $s5  = "K]++;}nVGPPwgDWTK++;} return XoTgCyXTcKz}" fullword ascii
    $s6  = "function bZIfrnkPxOZwPudgnSSiSQoSblyEVPfIAbjPQYBJNyjYupMfcQyHXG(CKxbPahQBdbFK,LZkpwqcpFfuxCs){ return OnHmk[SzoDx(CKxbPahQBdbFK[" ascii
    $s7  = "var B=new Array(\"2e\",\"2b\",\"2b\",\"2e\",\"2b\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s8  = "OoJmPGhHn[nVGPPwgDWTK]=(-292+292)/308; while(true) { if(OoJmPGhHn[nVGPPwgDWTK] > bPeNd[nVGPPwgDWTK].length-(-226+717)/491) { bre" ascii
    $s9  = " Ysbcc;}function pPfRGZVKbiLRYsH(MNNwUPUZlOHyIMkCS){eval(MNNwUPUZlOHyIMkCS)}" fullword ascii
    $s10 = "var B=new Array(\"2e\",\"2b\",\"2b\",\"2e\",\"2b\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s11 = "function SzoDx(YIERBSMSBNq,sVKgTLkJcOAXk,WLkLhwBY){EEPa=parseInt(YIERBSMSBNq,sVKgTLkJcOAXk);Ysbcc=EEPa.toString(WLkLhwBY);return" ascii
    $s12 = "function SzoDx(YIERBSMSBNq,sVKgTLkJcOAXk,WLkLhwBY){EEPa=parseInt(YIERBSMSBNq,sVKgTLkJcOAXk);Ysbcc=EEPa.toString(WLkLhwBY);return" ascii
    $s13 = "var e=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"38\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "var e=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"38\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s15 = "function FkaceUzsCHs(NkJTUQXt,mrFxmZ){return NkJTUQXt.split(mrFxmZ)}" fullword ascii
    $s16 = "function JMudolZfuvWuFuJES(bPeNd){XoTgCyXTcKz= '';nVGPPwgDWTK=(-401+401)/474; while(true){if(nVGPPwgDWTK >= (658+978)/818)break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}