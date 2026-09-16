rule TTP_XOR_QUAD_CurrentVersionRun_d633 {
  strings:
    $key_d633 = { 85 5c [2] a1 52 [2] 8a 7e [2] a4 5c [2] b0 47 [2] bf 5d [2] a1 40 [2] a3 41 [2] b8 47 [2] a4 40 [2] b8 6f }

  condition:
    any of them
}