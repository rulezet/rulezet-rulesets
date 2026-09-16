rule TTP_XOR_QUAD_CurrentVersionRun_c126 {
  strings:
    $key_c126 = { 92 49 [2] b6 47 [2] 9d 6b [2] b3 49 [2] a7 52 [2] a8 48 [2] b6 55 [2] b4 54 [2] af 52 [2] b3 55 [2] af 7a }

  condition:
    any of them
}