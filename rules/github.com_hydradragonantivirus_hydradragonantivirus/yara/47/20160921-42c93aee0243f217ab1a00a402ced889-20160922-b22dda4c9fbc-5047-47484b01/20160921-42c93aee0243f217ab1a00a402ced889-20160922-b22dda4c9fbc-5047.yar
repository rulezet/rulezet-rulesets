rule _20160921_42c93aee0243f217ab1a00a402ced889_20160922_b22dda4c9fbc_5047 {
  meta:
    description = "datamaliciousorder - from files 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash2       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = " f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"" ascii
    $s2 = "rn \"Qa\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s3 = "on f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s4 = "\"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(funct" ascii
    $s5 = "(function f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}