rule TTP_XOR_QUAD_CurrentVersionRun_c458 {
  strings:
    $key_c458 = { 97 37 [2] b3 39 [2] 98 15 [2] b6 37 [2] a2 2c [2] ad 36 [2] b3 2b [2] b1 2a [2] aa 2c [2] b6 2b [2] aa 04 }

  condition:
    any of them
}