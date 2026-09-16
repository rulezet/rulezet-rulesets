rule TTP_XOR_QUAD_CurrentVersionRun_c666 {
  strings:
    $key_c666 = { 95 09 [2] b1 07 [2] 9a 2b [2] b4 09 [2] a0 12 [2] af 08 [2] b1 15 [2] b3 14 [2] a8 12 [2] b4 15 [2] a8 3a }

  condition:
    any of them
}