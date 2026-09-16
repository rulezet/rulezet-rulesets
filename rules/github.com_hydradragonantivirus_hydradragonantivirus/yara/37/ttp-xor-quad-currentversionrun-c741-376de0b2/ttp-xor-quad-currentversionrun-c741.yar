rule TTP_XOR_QUAD_CurrentVersionRun_c741 {
  strings:
    $key_c741 = { 94 2e [2] b0 20 [2] 9b 0c [2] b5 2e [2] a1 35 [2] ae 2f [2] b0 32 [2] b2 33 [2] a9 35 [2] b5 32 [2] a9 1d }

  condition:
    any of them
}