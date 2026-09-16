rule TTP_XOR_QUAD_CurrentVersionRun_d133 {
  strings:
    $key_d133 = { 82 5c [2] a6 52 [2] 8d 7e [2] a3 5c [2] b7 47 [2] b8 5d [2] a6 40 [2] a4 41 [2] bf 47 [2] a3 40 [2] bf 6f }

  condition:
    any of them
}