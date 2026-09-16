rule TTP_XOR_QUAD_CurrentVersionRun_cdf0 {
  strings:
    $key_cdf0 = { 9e 9f [2] ba 91 [2] 91 bd [2] bf 9f [2] ab 84 [2] a4 9e [2] ba 83 [2] b8 82 [2] a3 84 [2] bf 83 [2] a3 ac }

  condition:
    any of them
}