rule TTP_XOR_QUAD_CurrentVersionRun_c131 {
  strings:
    $key_c131 = { 92 5e [2] b6 50 [2] 9d 7c [2] b3 5e [2] a7 45 [2] a8 5f [2] b6 42 [2] b4 43 [2] af 45 [2] b3 42 [2] af 6d }

  condition:
    any of them
}