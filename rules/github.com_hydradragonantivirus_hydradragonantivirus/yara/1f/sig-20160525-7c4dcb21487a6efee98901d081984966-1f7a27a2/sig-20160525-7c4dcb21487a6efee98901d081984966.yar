rule sig_20160525_7c4dcb21487a6efee98901d081984966 {
  meta:
    description = "datamaliciousorder - file 20160525_7c4dcb21487a6efee98901d081984966.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc1ecffb7a671ae4e5e8b926784c5aa644f0d9ccb1f3764e34f36db380c18c0e"

  strings:
    $s1  = "function PtUHObin(CjKaFSibMGIkH) {var OEQHCdMDpBVFRDfId = gByyuFj.join(wQQDOmAvKwomFMYwUWFTO[0]);var nGAMmeM, snHMg, VaNqkSbBHlS" ascii
    $s2  = "Swom == (679 + Math.round((Math.pow(Math.sin(611), 2) + Math.pow(Math.cos(611), 2) - 1))-615)) HaQFSfHXMt += sm(nGAMmeM);else if" ascii
    $s3  = "function PxZdgRpImiQRoyjAG(VCGgidFMQiWJ,UmMWhwqxlukHuW){return VCGgidFMQiWJ.charAt(UmMWhwqxlukHuW);}" fullword ascii
    $s4  = "MGIkH.length);return HaQFSfHXMt;}" fullword ascii
    $s5  = "function PtUHObin(CjKaFSibMGIkH) {var OEQHCdMDpBVFRDfId = gByyuFj.join(wQQDOmAvKwomFMYwUWFTO[0]);var nGAMmeM, snHMg, VaNqkSbBHlS" ascii
    $s6  = "function aQNgxH(esZcEx,QDxkeY){return esZcEx.indexOf(QDxkeY);}" fullword ascii
    $s7  = "function sm(WurJTAnzxwCDvfjKjlLvKp){return String.fromCharCode(WurJTAnzxwCDvfjKjlLvKp);}" fullword ascii
    $s8  = "function HfUVxhQfHvrwUxJbNL(PUMlKKQcHzOXfbfFmMxaZ,WdYwPaDXjBbPaLHUHdDBrK){return String.fromCharCode(PUMlKKQcHzOXfbfFmMxaZ,WdYwP" ascii
    $s9  = " HfUVxhQfHvrwUxJbNL(nGAMmeM, snHMg);else HaQFSfHXMt += gvDyKLQYfcZVxP(nGAMmeM, snHMg, VaNqkSbBHlSMaqA);} while (eHDDe < CjKaFSib" ascii
    $s10 = "function gvDyKLQYfcZVxP(CLjflKrSOIqnJdqAhorwxOAW,CqKxvJmxeQXgD,heBolxRzpaRFpxMsrFgasg){return String.fromCharCode(CLjflKrSOIqnJd" ascii
    $s11 = "function gvDyKLQYfcZVxP(CLjflKrSOIqnJdqAhorwxOAW,CqKxvJmxeQXgD,heBolxRzpaRFpxMsrFgasg){return String.fromCharCode(CLjflKrSOIqnJd" ascii
    $s12 = "function HfUVxhQfHvrwUxJbNL(PUMlKKQcHzOXfbfFmMxaZ,WdYwPaDXjBbPaLHUHdDBrK){return String.fromCharCode(PUMlKKQcHzOXfbfFmMxaZ,WdYwP" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}