rule _20160921_033cb159a63153428b22d38108b692e4_20160921_6f40563df6af_1435 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash3       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"
    hash4       = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"

  strings:
    $s1  = "f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KD" ascii
    $s2  = "0(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\"" ascii
    $s3  = "tion f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return" ascii
    $s4  = "{return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"OMd\";})(" ascii
    $s5  = "})(),(function f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f00" ascii
    $s6  = "n \"Ot\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(func" ascii
    $s7  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return " ascii
    $s8  = "000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn" ascii
    $s9  = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Vj\";})(),(function f0" ascii
    $s10 = ",(function f000(){return \"EZu\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Qa\";})(),(function f000(){" ascii
    $s11 = "),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){" ascii
    $s12 = "turn \"NYh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})()," ascii
    $s13 = "urn \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Vj\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}