rule TTP_XOR_QUAD_CurrentVersionRun_c106 {
  strings:
    $key_c106 = { 92 69 [2] b6 67 [2] 9d 4b [2] b3 69 [2] a7 72 [2] a8 68 [2] b6 75 [2] b4 74 [2] af 72 [2] b3 75 [2] af 5a }

  condition:
    any of them
}