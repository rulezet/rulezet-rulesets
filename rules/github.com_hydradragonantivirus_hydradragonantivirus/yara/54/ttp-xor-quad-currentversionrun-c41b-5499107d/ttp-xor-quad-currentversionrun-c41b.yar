rule TTP_XOR_QUAD_CurrentVersionRun_c41b {
  strings:
    $key_c41b = { 97 74 [2] b3 7a [2] 98 56 [2] b6 74 [2] a2 6f [2] ad 75 [2] b3 68 [2] b1 69 [2] aa 6f [2] b6 68 [2] aa 47 }

  condition:
    any of them
}