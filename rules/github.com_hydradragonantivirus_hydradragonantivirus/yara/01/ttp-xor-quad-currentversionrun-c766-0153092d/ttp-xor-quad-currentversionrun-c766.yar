rule TTP_XOR_QUAD_CurrentVersionRun_c766 {
  strings:
    $key_c766 = { 94 09 [2] b0 07 [2] 9b 2b [2] b5 09 [2] a1 12 [2] ae 08 [2] b0 15 [2] b2 14 [2] a9 12 [2] b5 15 [2] a9 3a }

  condition:
    any of them
}