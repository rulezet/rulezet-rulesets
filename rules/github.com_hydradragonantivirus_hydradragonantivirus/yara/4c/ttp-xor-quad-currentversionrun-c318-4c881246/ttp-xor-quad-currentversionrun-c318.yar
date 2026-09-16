rule TTP_XOR_QUAD_CurrentVersionRun_c318 {
  strings:
    $key_c318 = { 90 77 [2] b4 79 [2] 9f 55 [2] b1 77 [2] a5 6c [2] aa 76 [2] b4 6b [2] b6 6a [2] ad 6c [2] b1 6b [2] ad 44 }

  condition:
    any of them
}