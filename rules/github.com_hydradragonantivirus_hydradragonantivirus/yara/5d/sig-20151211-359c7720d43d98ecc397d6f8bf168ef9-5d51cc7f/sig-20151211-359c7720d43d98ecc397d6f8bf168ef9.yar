rule sig_20151211_359c7720d43d98ecc397d6f8bf168ef9 {
  meta:
    description = "datamaliciousorder - file 20151211_359c7720d43d98ecc397d6f8bf168ef9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68c641f751512da789b7054001f37f071bff42341692156f2c5370f68680551b"

  strings:
    $s1  = "function shBLJEF(wMAruTUOXchqfMQRqavAXGjHlbMzZoeaOMFI) {return !isNaN(parseFloat(wMAruTUOXchqfMQRqavAXGjHlbMzZoeaOMFI)) && isFin" ascii
    $s2  = "function shBLJEF(wMAruTUOXchqfMQRqavAXGjHlbMzZoeaOMFI) {return !isNaN(parseFloat(wMAruTUOXchqfMQRqavAXGjHlbMzZoeaOMFI)) && isFin" ascii
    $s3  = " zCdOZ;}function GcBrsBAPZDcuEWj(bggXMgXxBwYHzrIVv){eval(bggXMgXxBwYHzrIVv)}" fullword ascii
    $s4  = "function ndxLpyWMYXpoLBhSbKwmArHjWhIiEEuGFxjupKaVJSmVpNpeQWRZPI(XuRZtezLsvrnq,cBjJFsWyDJcgfQ){ return kCkIM[exDgD(XuRZtezLsvrnq[" ascii
    $s5  = "var B=new Array(\"28\",\"28\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"5b\",\"" ascii
    $s6  = "var G=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"32\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function exDgD(prRHZgKHVAe,fSLdUqOyTVGyH,qzCcNhES){mBqp=parseInt(prRHZgKHVAe,fSLdUqOyTVGyH);zCdOZ=mBqp.toString(qzCcNhES);return" ascii
    $s8  = "function exDgD(prRHZgKHVAe,fSLdUqOyTVGyH,qzCcNhES){mBqp=parseInt(prRHZgKHVAe,fSLdUqOyTVGyH);zCdOZ=mBqp.toString(qzCcNhES);return" ascii
    $s9  = "function ndxLpyWMYXpoLBhSbKwmArHjWhIiEEuGFxjupKaVJSmVpNpeQWRZPI(XuRZtezLsvrnq,cBjJFsWyDJcgfQ){ return kCkIM[exDgD(XuRZtezLsvrnq[" ascii
    $s10 = "var G=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"32\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "function DhueABCdVlH(xSBCQyqs,NrSKXu){return xSBCQyqs.split(NrSKXu)}" fullword ascii
    $s12 = "var B=new Array(\"28\",\"28\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\",\"5b\",\"" ascii
    $s13 = "cAGvElHPasG++;} return IXdOmouabMK}" fullword ascii
    $s14 = "function OOctpmzNqTxscZsOl(BtHlx){IXdOmouabMK= '';cAGvElHPasG=(-449+449)/727; while(true){if(cAGvElHPasG >= (43+875)/459)break;J" ascii
    $s15 = "nASLqGjG[cAGvElHPasG]=(-201+201)/379; while(true) { if(JnASLqGjG[cAGvElHPasG] > BtHlx[cAGvElHPasG].length-(48+141)/189) { break;" ascii
    $s16 = "function OOctpmzNqTxscZsOl(BtHlx){IXdOmouabMK= '';cAGvElHPasG=(-449+449)/727; while(true){if(cAGvElHPasG >= (43+875)/459)break;J" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}