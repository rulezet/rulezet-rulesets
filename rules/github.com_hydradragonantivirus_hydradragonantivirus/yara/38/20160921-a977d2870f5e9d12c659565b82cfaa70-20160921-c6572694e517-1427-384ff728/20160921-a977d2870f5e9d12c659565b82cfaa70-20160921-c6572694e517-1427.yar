rule _20160921_a977d2870f5e9d12c659565b82cfaa70_20160921_c6572694e517_1427 {
  meta:
    description = "datamaliciousorder - from files 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js, 20160921_d7492227e681b1689bfc5442a91a169e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash2       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"
    hash3       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"

  strings:
    $s1  = "unction f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){re" ascii
    $s2  = ",(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(function f000(){r" ascii
    $s3  = "\"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s4  = "(),(function f000(){return \"SGs\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s5  = "eturn \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vu\";})(),(" ascii
    $s6  = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"RLk\";})(),(f" ascii
    $s7  = "00(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";" ascii
    $s8  = " \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(fu" ascii
    $s9  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MMz\";})(),(function f00" ascii
    $s10 = "ction f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s11 = "turn \"Nx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKp\";})(),(" ascii
    $s12 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"" ascii
    $s13 = "urn \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})()," ascii
    $s14 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}