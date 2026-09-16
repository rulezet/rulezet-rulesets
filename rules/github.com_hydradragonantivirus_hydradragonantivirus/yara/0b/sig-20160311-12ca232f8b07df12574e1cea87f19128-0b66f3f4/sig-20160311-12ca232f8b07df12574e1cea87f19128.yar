rule sig_20160311_12ca232f8b07df12574e1cea87f19128 {
  meta:
    description = "datamaliciousorder - file 20160311_12ca232f8b07df12574e1cea87f19128.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3fd2e376874dcf27a7b5726df71ec643590afb6df6d1e0016f6ee05107db70f"

  strings:
    $s1  = "return SFNzIYv[0] + SFNzIYv[2] + SFNzIYv[4] + \".F\" + SFNzIYv[7] + SFNzIYv[9] + SFNzIYv[12] + SFNzIYv[14];" fullword ascii
    $s2  = "var nk = true  , VKyl = oFc[7] + oFc[9] + oFc[11];" fullword ascii
    $s3  = "var oFc = (\"2.XMLHTTP XYISuhv BkpXg XML ream St KImVKjgd AD wBLnhNg O VaBy D\").split(\" \");" fullword ascii
    $s4  = "var SFNzIYv = \"Sc uOHDJDq r hYzMTkwtq ipting ppZwnUB WTK ile keKmEXpuIQmHgS System RN LYtDN Obj BAAWYO ect ChuTsTN\".split(\" " ascii
    $s5  = "ikYdF.open(uctgE,gcUPg,false);" fullword ascii
    $s6  = "function qLCZr(yBRuby) {" fullword ascii
    $s7  = "return gdbog;" fullword ascii
    $s8  = "function OctgCiEg(RZK) {" fullword ascii
    $s9  = "function NDJu(HJHBW) {" fullword ascii
    $s10 = "return KfzB.ExpandEnvironmentStrings(uRZFC);" fullword ascii
    $s11 = "function WCGn(ikYdF,gcUPg,uctgE) {" fullword ascii
    $s12 = "function bFrZ(FfOlN,rjTOx) {" fullword ascii
    $s13 = "function YAia(CWHPe) {" fullword ascii
    $s14 = "return FMUb.responseBody;" fullword ascii
    $s15 = "function gtkXNzfy(zlArU,eHZXHN) {" fullword ascii
    $s16 = "return yBRuby.position=616-616;" fullword ascii
    $s17 = "return kKTcI.status;" fullword ascii
    $s18 = "function zLkp(QgsIO) {" fullword ascii
    $s19 = "function Mjoa(kKTcI) {" fullword ascii
    $s20 = "function IawZGbKfY() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}