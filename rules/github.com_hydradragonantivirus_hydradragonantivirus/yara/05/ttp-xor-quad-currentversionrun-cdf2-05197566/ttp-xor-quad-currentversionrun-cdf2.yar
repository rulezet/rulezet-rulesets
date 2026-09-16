rule TTP_XOR_QUAD_CurrentVersionRun_cdf2 {
  strings:
    $key_cdf2 = { 9e 9d [2] ba 93 [2] 91 bf [2] bf 9d [2] ab 86 [2] a4 9c [2] ba 81 [2] b8 80 [2] a3 86 [2] bf 81 [2] a3 ae }

  condition:
    any of them
}