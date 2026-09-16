rule _20160921_6f40563df6afd13be332d60057d492bb_20160921_c9a772728edf_5379 {
  meta:
    description = "datamaliciousorder - from files 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash2       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash3       = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"
    hash4       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = "urn \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s2 = ",(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){" ascii
    $s3 = "00(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn" ascii
    $s4 = "unction f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){re" ascii
    $s5 = "rn \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}