rule TTP_XOR_QUAD_CurrentVersionRun_d17f {
  strings:
    $key_d17f = { 82 10 [2] a6 1e [2] 8d 32 [2] a3 10 [2] b7 0b [2] b8 11 [2] a6 0c [2] a4 0d [2] bf 0b [2] a3 0c [2] bf 23 }

  condition:
    any of them
}