rule _20160921_d29f521c8121911a610a80bcc76b94bf_20160921_da4ec6dae2ec_2571 {
  meta:
    description = "datamaliciousorder - from files 20160921_d29f521c8121911a610a80bcc76b94bf.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"
    hash2       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"

  strings:
    $s1 = ")(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii
    $s2 = "return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})()" ascii
    $s3 = "return \"IAa\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s4 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s5 = "tion f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTi\";})(),(function f000(){retur" ascii
    $s6 = "nction f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Oe\";})(),(function f000(){retur" ascii
    $s7 = "eturn \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"YTp\";})(" ascii
    $s8 = "ion f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}