rule TTP_XOR_QUAD_CurrentVersionRun_c478 {
  strings:
    $key_c478 = { 97 17 [2] b3 19 [2] 98 35 [2] b6 17 [2] a2 0c [2] ad 16 [2] b3 0b [2] b1 0a [2] aa 0c [2] b6 0b [2] aa 24 }

  condition:
    any of them
}