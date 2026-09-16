rule _20160921_18cdf3dec8ac4b7697e775bc56ddeba9_20160921_527d7c375697_157 {
  meta:
    description = "datamaliciousorder - from files 20160921_18cdf3dec8ac4b7697e775bc56ddeba9.js, 20160921_527d7c3756974f804734da343b6b6f0e.js, 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_814eb57aeffc75442964829345cc9f96.js, 20160921_89a260f4d6da4d97f251f843cf5e94b0.js, 20160921_b86272ed73cef9077c204056df823014.js, 20160921_d7492227e681b1689bfc5442a91a169e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1aa090c906360f52952b29d512b8c450c7e8c8cff28bc6fded6af15377b37c"
    hash2       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"
    hash3       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash4       = "2736df4d651a33824aba7abffa7c08414414ffed9f5f27b4b2d81101cfeb7117"
    hash5       = "700f6c802eb024896efe2b22255973b53752a8f129213c9bba2c4f2ebdc53988"
    hash6       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"
    hash7       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"

  strings:
    $s1  = "{return \"MBb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})" ascii
    $s2  = "00(){return \"BQb\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Br\";" ascii
    $s3  = "){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wy\";})(" ascii
    $s4  = "urn \"Sv\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s5  = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"D" ascii
    $s6  = "urn \"Yi\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s7  = "000(){return \"Wb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn" ascii
    $s8  = "tion f000(){return \"TKp\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii
    $s9  = "n f000(){return \"PTi\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii
    $s10 = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Mc" ascii
    $s11 = "(function f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s12 = "0(){return \"Oe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";}" ascii
    $s13 = "n f000(){return \"Br\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"K" ascii
    $s14 = "r\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MMz\";})(),(functio" ascii
    $s15 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Tb\";})(),(function f000(){r" ascii
    $s16 = "nction f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){retur" ascii
    $s17 = "nction f000(){return \"IAa\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MJq\";})(),(function f000(){retu" ascii
    $s18 = "urn \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Br\";})(),(f" ascii
    $s19 = "n f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"" ascii
    $s20 = "n \"TKp\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}