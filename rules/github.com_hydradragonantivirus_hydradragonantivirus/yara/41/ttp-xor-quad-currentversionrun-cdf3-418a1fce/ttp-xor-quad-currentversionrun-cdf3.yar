rule TTP_XOR_QUAD_CurrentVersionRun_cdf3 {
  strings:
    $key_cdf3 = { 9e 9c [2] ba 92 [2] 91 be [2] bf 9c [2] ab 87 [2] a4 9d [2] ba 80 [2] b8 81 [2] a3 87 [2] bf 80 [2] a3 af }

  condition:
    any of them
}