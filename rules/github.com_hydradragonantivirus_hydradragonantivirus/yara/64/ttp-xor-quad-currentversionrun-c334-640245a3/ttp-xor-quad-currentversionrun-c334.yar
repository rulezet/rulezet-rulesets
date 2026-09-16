rule TTP_XOR_QUAD_CurrentVersionRun_c334 {
  strings:
    $key_c334 = { 90 5b [2] b4 55 [2] 9f 79 [2] b1 5b [2] a5 40 [2] aa 5a [2] b4 47 [2] b6 46 [2] ad 40 [2] b1 47 [2] ad 68 }

  condition:
    any of them
}