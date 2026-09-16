rule TTP_XOR_QUAD_CurrentVersionRun_d13d {
  strings:
    $key_d13d = { 82 52 [2] a6 5c [2] 8d 70 [2] a3 52 [2] b7 49 [2] b8 53 [2] a6 4e [2] a4 4f [2] bf 49 [2] a3 4e [2] bf 61 }

  condition:
    any of them
}