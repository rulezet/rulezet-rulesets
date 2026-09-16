rule TTP_XOR_QUAD_CurrentVersionRun_c176 {
  strings:
    $key_c176 = { 92 19 [2] b6 17 [2] 9d 3b [2] b3 19 [2] a7 02 [2] a8 18 [2] b6 05 [2] b4 04 [2] af 02 [2] b3 05 [2] af 2a }

  condition:
    any of them
}