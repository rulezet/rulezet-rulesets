rule _20160921_382a0f9b1ae693f8ade627fd2d6a8b52_20160921_54325d6949c5_4937 {
  meta:
    description = "datamaliciousorder - from files 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash2       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash3       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash4       = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"

  strings:
    $s1 = "urn \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})()," ascii
    $s2 = "eturn \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s3 = "turn \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})()," ascii
    $s4 = "0(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";" ascii
    $s5 = "n f000(){return \"Wh\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"T" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}