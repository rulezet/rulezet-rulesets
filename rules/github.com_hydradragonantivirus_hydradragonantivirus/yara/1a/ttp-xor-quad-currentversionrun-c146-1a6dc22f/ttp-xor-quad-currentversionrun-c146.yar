rule TTP_XOR_QUAD_CurrentVersionRun_c146 {
  strings:
    $key_c146 = { 92 29 [2] b6 27 [2] 9d 0b [2] b3 29 [2] a7 32 [2] a8 28 [2] b6 35 [2] b4 34 [2] af 32 [2] b3 35 [2] af 1a }

  condition:
    any of them
}