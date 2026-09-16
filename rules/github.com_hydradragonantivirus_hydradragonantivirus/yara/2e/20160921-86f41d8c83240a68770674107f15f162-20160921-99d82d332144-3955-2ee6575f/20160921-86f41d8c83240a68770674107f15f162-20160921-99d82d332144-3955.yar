rule _20160921_86f41d8c83240a68770674107f15f162_20160921_99d82d332144_3955 {
  meta:
    description = "datamaliciousorder - from files 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_99d82d33214407e421e255b85f02daae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash2       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"

  strings:
    $s1 = ")(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(" ascii
    $s2 = "f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"N" ascii
    $s3 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi" ascii
    $s4 = "00(){return \"TKp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs" ascii
    $s5 = "rn \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s6 = "){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}