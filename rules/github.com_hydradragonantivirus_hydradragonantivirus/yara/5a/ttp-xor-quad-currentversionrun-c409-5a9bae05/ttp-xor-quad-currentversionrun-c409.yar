rule TTP_XOR_QUAD_CurrentVersionRun_c409 {
  strings:
    $key_c409 = { 97 66 [2] b3 68 [2] 98 44 [2] b6 66 [2] a2 7d [2] ad 67 [2] b3 7a [2] b1 7b [2] aa 7d [2] b6 7a [2] aa 55 }

  condition:
    any of them
}