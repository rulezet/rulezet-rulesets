rule _20160921_8b0f3892ae56f8c06d3baa62c262a12f_20160921_ad69715850fa_5521 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_ad69715850fae108d9a16055efb4f51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash2       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"

  strings:
    $s1 = "rn \"BIj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(fun" ascii
    $s2 = "),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s3 = ",(function f000(){return \"Sq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(function f000(){r" ascii
    $s4 = " f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"B" ascii
    $s5 = "urn \"Sv\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}