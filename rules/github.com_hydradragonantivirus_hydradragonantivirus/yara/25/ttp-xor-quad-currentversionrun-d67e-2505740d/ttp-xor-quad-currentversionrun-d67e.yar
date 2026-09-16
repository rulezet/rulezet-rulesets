rule TTP_XOR_QUAD_CurrentVersionRun_d67e {
  strings:
    $key_d67e = { 85 11 [2] a1 1f [2] 8a 33 [2] a4 11 [2] b0 0a [2] bf 10 [2] a1 0d [2] a3 0c [2] b8 0a [2] a4 0d [2] b8 22 }

  condition:
    any of them
}