rule TTP_XOR_QUAD_CurrentVersionRun_c631 {
  strings:
    $key_c631 = { 95 5e [2] b1 50 [2] 9a 7c [2] b4 5e [2] a0 45 [2] af 5f [2] b1 42 [2] b3 43 [2] a8 45 [2] b4 42 [2] a8 6d }

  condition:
    any of them
}