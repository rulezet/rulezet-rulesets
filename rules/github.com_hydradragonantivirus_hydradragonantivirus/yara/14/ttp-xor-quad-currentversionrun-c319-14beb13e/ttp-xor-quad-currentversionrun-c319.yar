rule TTP_XOR_QUAD_CurrentVersionRun_c319 {
  strings:
    $key_c319 = { 90 76 [2] b4 78 [2] 9f 54 [2] b1 76 [2] a5 6d [2] aa 77 [2] b4 6a [2] b6 6b [2] ad 6d [2] b1 6a [2] ad 45 }

  condition:
    any of them
}