rule TTP_XOR_QUAD_CurrentVersionRun_cddb {
  strings:
    $key_cddb = { 9e b4 [2] ba ba [2] 91 96 [2] bf b4 [2] ab af [2] a4 b5 [2] ba a8 [2] b8 a9 [2] a3 af [2] bf a8 [2] a3 87 }

  condition:
    any of them
}