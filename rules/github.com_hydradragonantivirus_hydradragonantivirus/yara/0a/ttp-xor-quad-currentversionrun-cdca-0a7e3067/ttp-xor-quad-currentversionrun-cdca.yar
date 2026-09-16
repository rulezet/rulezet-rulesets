rule TTP_XOR_QUAD_CurrentVersionRun_cdca {
  strings:
    $key_cdca = { 9e a5 [2] ba ab [2] 91 87 [2] bf a5 [2] ab be [2] a4 a4 [2] ba b9 [2] b8 b8 [2] a3 be [2] bf b9 [2] a3 96 }

  condition:
    any of them
}