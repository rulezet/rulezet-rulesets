rule TTP_XOR_QUAD_CurrentVersionRun_c166 {
  strings:
    $key_c166 = { 92 09 [2] b6 07 [2] 9d 2b [2] b3 09 [2] a7 12 [2] a8 08 [2] b6 15 [2] b4 14 [2] af 12 [2] b3 15 [2] af 3a }

  condition:
    any of them
}