rule TTP_XOR_QUAD_CurrentVersionRun_c641 {
  strings:
    $key_c641 = { 95 2e [2] b1 20 [2] 9a 0c [2] b4 2e [2] a0 35 [2] af 2f [2] b1 32 [2] b3 33 [2] a8 35 [2] b4 32 [2] a8 1d }

  condition:
    any of them
}