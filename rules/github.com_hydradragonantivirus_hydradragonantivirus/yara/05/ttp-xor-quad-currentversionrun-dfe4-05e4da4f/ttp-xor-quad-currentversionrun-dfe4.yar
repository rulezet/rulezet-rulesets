rule TTP_XOR_QUAD_CurrentVersionRun_dfe4 {
  strings:
    $key_dfe4 = { 8c 8b [2] a8 85 [2] 83 a9 [2] ad 8b [2] b9 90 [2] b6 8a [2] a8 97 [2] aa 96 [2] b1 90 [2] ad 97 [2] b1 b8 }

  condition:
    any of them
}