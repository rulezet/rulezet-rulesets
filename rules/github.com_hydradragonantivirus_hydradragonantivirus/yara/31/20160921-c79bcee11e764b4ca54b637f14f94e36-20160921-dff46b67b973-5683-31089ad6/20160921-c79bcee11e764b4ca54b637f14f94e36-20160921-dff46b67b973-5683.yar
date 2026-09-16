rule _20160921_c79bcee11e764b4ca54b637f14f94e36_20160921_dff46b67b973_5683 {
  meta:
    description = "datamaliciousorder - from files 20160921_c79bcee11e764b4ca54b637f14f94e36.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"
    hash2       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"
    hash3       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = "f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy" ascii
    $s2 = "){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})" ascii
    $s3 = "turn \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(f" ascii
    $s4 = "function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){re" ascii
    $s5 = ";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}