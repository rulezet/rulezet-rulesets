rule sig_20160312_deed63ee4ec794b845a9f6aaacd5bc87 {
  meta:
    description = "datamaliciousorder - file 20160312_deed63ee4ec794b845a9f6aaacd5bc87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9051092aa2a4a4b393a16192a8e8ffee7ffd190a0e9fde26d4f1fc117e06910f"

  strings:
    $s1  = "var Ta = true  , TtAj = boS[7] + boS[9] + boS[11];" fullword ascii
    $s2  = "return jiWwcDd[0] + jiWwcDd[2] + jiWwcDd[4] + \".F\" + jiWwcDd[7] + jiWwcDd[9] + jiWwcDd[12] + jiWwcDd[14];" fullword ascii
    $s3  = "fbRGr.open(wbKWa,krlUe,false);" fullword ascii
    $s4  = "var boS = (\"2.XMLHTTP EjCrKCl eDrTQ XML ream St eYbSmvWL AD gTTtRtZ O Ssxn D\").split(\" \");" fullword ascii
    $s5  = "var jiWwcDd = \"Sc jZXOktA r OviDpZAdB ipting JqyvuIN Gro ile PYRGMOKCGLmxDe System iV vVVBZ Obj Jdeamm ect NqIewuG\".split(\" " ascii
    $s6  = "function mFKg(koBqP) {" fullword ascii
    $s7  = "function PsnNYvZUG(zPnUdstzSDH) {" fullword ascii
    $s8  = "return HlWd.responseBody;" fullword ascii
    $s9  = "return cyRwfN.position=336-336;" fullword ascii
    $s10 = "function rViWa(lZGLPe) {" fullword ascii
    $s11 = "function ZxTKQHv(Cxki,xZKnU) {" fullword ascii
    $s12 = "return tXKbB;" fullword ascii
    $s13 = "function eGPqOxoLP() {" fullword ascii
    $s14 = "function QQwUxLoS(eMm) {" fullword ascii
    $s15 = "if (cQxye > 134589-790){return true;} else {return false;}" fullword ascii
    $s16 = "function ItvdCWpg() {" fullword ascii
    $s17 = "function YIze(cQxye) {" fullword ascii
    $s18 = "function JBRL(gJAOF) {" fullword ascii
    $s19 = "if (j >= zaaFI.length) {break;}" fullword ascii
    $s20 = "function kjkm(zaaFI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}