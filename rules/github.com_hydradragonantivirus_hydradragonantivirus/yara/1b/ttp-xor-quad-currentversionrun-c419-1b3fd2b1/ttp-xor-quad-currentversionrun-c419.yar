rule TTP_XOR_QUAD_CurrentVersionRun_c419 {
  strings:
    $key_c419 = { 97 76 [2] b3 78 [2] 98 54 [2] b6 76 [2] a2 6d [2] ad 77 [2] b3 6a [2] b1 6b [2] aa 6d [2] b6 6a [2] aa 45 }

  condition:
    any of them
}