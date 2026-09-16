rule TTP_XOR_QUAD_CurrentVersionRun_c4f9 {
  strings:
    $key_c4f9 = { 97 96 [2] b3 98 [2] 98 b4 [2] b6 96 [2] a2 8d [2] ad 97 [2] b3 8a [2] b1 8b [2] aa 8d [2] b6 8a [2] aa a5 }

  condition:
    any of them
}