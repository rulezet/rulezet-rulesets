rule TTP_XOR_QUAD_CurrentVersionRun_c124 {
  strings:
    $key_c124 = { 92 4b [2] b6 45 [2] 9d 69 [2] b3 4b [2] a7 50 [2] a8 4a [2] b6 57 [2] b4 56 [2] af 50 [2] b3 57 [2] af 78 }

  condition:
    any of them
}