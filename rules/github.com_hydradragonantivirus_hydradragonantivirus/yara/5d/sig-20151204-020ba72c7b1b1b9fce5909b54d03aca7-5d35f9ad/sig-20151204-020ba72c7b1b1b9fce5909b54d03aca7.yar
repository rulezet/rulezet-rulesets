rule sig_20151204_020ba72c7b1b1b9fce5909b54d03aca7 {
  meta:
    description = "datamaliciousorder - file 20151204_020ba72c7b1b1b9fce5909b54d03aca7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c022ca4e8226215bcf8e833e0496852350c57634d233d28c086e95b96c8a2c"

  strings:
    $s1 = "function Xeiondz(nbVboRRlcRRovEPpEaMweQZcVbrbDojBhMyD) {return !isNaN(parseFloat(nbVboRRlcRRovEPpEaMweQZcVbrbDojBhMyD)) && isFin" ascii
    $s2 = "function Xeiondz(nbVboRRlcRRovEPpEaMweQZcVbrbDojBhMyD) {return !isNaN(parseFloat(nbVboRRlcRRovEPpEaMweQZcVbrbDojBhMyD)) && isFin" ascii
    $s3 = "function DAVtaiDEzyasMuzmemuPcVeVtRpjlYhZJXDEudNRjuqPQLeTvOpkEJ(TbaTWScNusToe,YnDmUxfXZzuGkf){ return String.fromCharCode(TbaTWS" ascii
    $s4 = "function HmVyuwctdDaFldt(zUYnDiehurDPfGlwn){eval(zUYnDiehurDPfGlwn)}" fullword ascii
    $s5 = "function KhbzTkZsgNJoQRJmM(SsBQotuoxxIfRg) { JcvoDSyTsQeI = ojCBtNbylrh(SsBQotuoxxIfRg,'" fullword ascii
    $s6 = "function DAVtaiDEzyasMuzmemuPcVeVtRpjlYhZJXDEudNRjuqPQLeTvOpkEJ(TbaTWScNusToe,YnDmUxfXZzuGkf){ return String.fromCharCode(TbaTWS" ascii
    $s7 = "function ojCBtNbylrh(fKAdofSE,WpIGup){return fKAdofSE.split(WpIGup)}" fullword ascii
    $s8 = "'); FVORlSXBvyQ= ''; for(IWkOJfTzDTtMOmgqIIEJtiROb=0; IWkOJfTzDTtMOmgqIIEJtiROb < JcvoDSyTsQeI.length; IWkOJfTzDTtMOmgqIIEJtiROb" ascii
    $s9 = "EJ([JcvoDSyTsQeI[IWkOJfTzDTtMOmgqIIEJtiROb]], 0);}} return FVORlSXBvyQ}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}