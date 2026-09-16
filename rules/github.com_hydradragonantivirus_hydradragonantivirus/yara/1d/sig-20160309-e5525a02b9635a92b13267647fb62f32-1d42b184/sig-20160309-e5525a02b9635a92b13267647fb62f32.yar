rule sig_20160309_e5525a02b9635a92b13267647fb62f32 {
  meta:
    description = "datamaliciousorder - file 20160309_e5525a02b9635a92b13267647fb62f32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1af82c782877d943a137a3d7de610cb2cfc8871879de4912d6b5cc3c6cb0acea"

  strings:
    $s1  = "function zPZsinhGI(RNqeyEdIbec) {" fullword ascii
    $s2  = "var Wy = true  , sUxQ = IaO[7] + IaO[9] + IaO[11];" fullword ascii
    $s3  = "return YUNPBXM[0] + YUNPBXM[2] + YUNPBXM[4] + \".F\" + YUNPBXM[7] + YUNPBXM[9] + YUNPBXM[12] + YUNPBXM[14];" fullword ascii
    $s4  = "XcMUc.open(eBain,ABpNM,false);" fullword ascii
    $s5  = "var YUNPBXM = \"Sc kNimcZh r gAeAlpLSq ipting MoSHodY IeL ile uFSbAdZyEbCwha System lt FmIiB Obj PstxLq ect ziMcXKU\".split(\" " ascii
    $s6  = "var IaO = (\"2.XMLHTTP bWKvmoW veNga XML ream St jnObUVsc AD YoqwwHe O PyNp D\").split(\" \");" fullword ascii
    $s7  = "return TzOr.ExpandEnvironmentStrings(AwItl);" fullword ascii
    $s8  = "function eLBQ(HvODj) {" fullword ascii
    $s9  = "function rOEbCwn(BsWu) {" fullword ascii
    $s10 = "if (yIdOH > 152943-809){return true;} else {return false;}" fullword ascii
    $s11 = "return NDVho.status;" fullword ascii
    $s12 = "iOZ = s; break; " fullword ascii
    $s13 = "function Yrfljhdu() {" fullword ascii
    $s14 = "function zsnIPTdp(oup) {" fullword ascii
    $s15 = "if (HfTti == 500-300){return true;} else {return false;}" fullword ascii
    $s16 = "if (U >= HvODj.length) {break;}" fullword ascii
    $s17 = "function WNyx(NDVho) {" fullword ascii
    $s18 = "return VUnnH;" fullword ascii
    $s19 = "function fiWLW(FZkmth) {" fullword ascii
    $s20 = "function VdRnTMC(TzOr,AwItl) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}