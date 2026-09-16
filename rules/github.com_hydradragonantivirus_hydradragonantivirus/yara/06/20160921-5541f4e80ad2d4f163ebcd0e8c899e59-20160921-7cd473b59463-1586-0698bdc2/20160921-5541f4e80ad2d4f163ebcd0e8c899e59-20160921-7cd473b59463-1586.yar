rule _20160921_5541f4e80ad2d4f163ebcd0e8c899e59_20160921_7cd473b59463_1586 {
  meta:
    description = "datamaliciousorder - from files 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_7cd473b59463126782b9a6cfaae72835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash2       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"

  strings:
    $s1  = "tion f000(){return \"Br\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s2  = "urn \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(f" ascii
    $s3  = "000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\"" ascii
    $s4  = "){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";}" ascii
    $s5  = "{return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()" ascii
    $s6  = "(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s7  = "ion f000(){return \"ZGq\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s8  = "tion f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s9  = "(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";}" ascii
    $s10 = "rn \"Rh\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s11 = "nction f000(){return \"Sv\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s12 = "(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}