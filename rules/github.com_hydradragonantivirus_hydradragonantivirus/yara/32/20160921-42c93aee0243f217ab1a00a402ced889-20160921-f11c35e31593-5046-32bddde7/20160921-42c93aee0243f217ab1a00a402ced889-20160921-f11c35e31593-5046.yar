rule _20160921_42c93aee0243f217ab1a00a402ced889_20160921_f11c35e31593_5046 {
  meta:
    description = "datamaliciousorder - from files 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash2       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1 = "tion f000(){return \"OUx\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return" ascii
    $s2 = "),(function f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s3 = "{return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})" ascii
    $s4 = "nction f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){ret" ascii
    $s5 = "eturn \"ZIi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}