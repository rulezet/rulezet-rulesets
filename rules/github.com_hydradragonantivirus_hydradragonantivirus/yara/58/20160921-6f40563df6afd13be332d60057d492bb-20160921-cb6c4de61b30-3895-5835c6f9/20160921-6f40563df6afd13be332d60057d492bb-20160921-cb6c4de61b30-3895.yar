rule _20160921_6f40563df6afd13be332d60057d492bb_20160921_cb6c4de61b30_3895 {
  meta:
    description = "datamaliciousorder - from files 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_cb6c4de61b30cd204129d0942321058c.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash2       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"
    hash3       = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"

  strings:
    $s1 = "s\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(functio" ascii
    $s2 = "unction f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sv\";})(),(function f000(){retu" ascii
    $s3 = "n f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"" ascii
    $s4 = "),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"DYx\";})(),(function f000()" ascii
    $s5 = "urn \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"UEg\";})(),(fu" ascii
    $s6 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Qj\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}