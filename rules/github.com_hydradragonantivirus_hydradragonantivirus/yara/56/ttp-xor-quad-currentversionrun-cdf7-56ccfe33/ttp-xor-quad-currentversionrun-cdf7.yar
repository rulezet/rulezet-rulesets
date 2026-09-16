rule TTP_XOR_QUAD_CurrentVersionRun_cdf7 {
  strings:
    $key_cdf7 = { 9e 98 [2] ba 96 [2] 91 ba [2] bf 98 [2] ab 83 [2] a4 99 [2] ba 84 [2] b8 85 [2] a3 83 [2] bf 84 [2] a3 ab }

  condition:
    any of them
}