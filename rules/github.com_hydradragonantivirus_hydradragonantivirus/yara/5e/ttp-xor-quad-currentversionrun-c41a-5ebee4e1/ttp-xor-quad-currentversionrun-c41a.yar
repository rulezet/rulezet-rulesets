rule TTP_XOR_QUAD_CurrentVersionRun_c41a {
  strings:
    $key_c41a = { 97 75 [2] b3 7b [2] 98 57 [2] b6 75 [2] a2 6e [2] ad 74 [2] b3 69 [2] b1 68 [2] aa 6e [2] b6 69 [2] aa 46 }

  condition:
    any of them
}