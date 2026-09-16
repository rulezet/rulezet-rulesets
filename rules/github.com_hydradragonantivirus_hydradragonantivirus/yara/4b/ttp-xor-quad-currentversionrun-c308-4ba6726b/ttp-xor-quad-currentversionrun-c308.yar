rule TTP_XOR_QUAD_CurrentVersionRun_c308 {
  strings:
    $key_c308 = { 90 67 [2] b4 69 [2] 9f 45 [2] b1 67 [2] a5 7c [2] aa 66 [2] b4 7b [2] b6 7a [2] ad 7c [2] b1 7b [2] ad 54 }

  condition:
    any of them
}