rule TTP_XOR_QUAD_CurrentVersionRun_d641 {
  strings:
    $key_d641 = { 85 2e [2] a1 20 [2] 8a 0c [2] a4 2e [2] b0 35 [2] bf 2f [2] a1 32 [2] a3 33 [2] b8 35 [2] a4 32 [2] b8 1d }

  condition:
    any of them
}