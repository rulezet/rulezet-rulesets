rule TTP_XOR_QUAD_CurrentVersionRun_dec6 {
  strings:
    $key_dec6 = { 8d a9 [2] a9 a7 [2] 82 8b [2] ac a9 [2] b8 b2 [2] b7 a8 [2] a9 b5 [2] ab b4 [2] b0 b2 [2] ac b5 [2] b0 9a }

  condition:
    any of them
}