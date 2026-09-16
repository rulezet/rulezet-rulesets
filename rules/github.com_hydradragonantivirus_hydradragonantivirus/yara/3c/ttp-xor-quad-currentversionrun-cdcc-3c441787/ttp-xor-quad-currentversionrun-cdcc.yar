rule TTP_XOR_QUAD_CurrentVersionRun_cdcc {
  strings:
    $key_cdcc = { 9e a3 [2] ba ad [2] 91 81 [2] bf a3 [2] ab b8 [2] a4 a2 [2] ba bf [2] b8 be [2] a3 b8 [2] bf bf [2] a3 90 }

  condition:
    any of them
}