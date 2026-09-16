rule TTP_XOR_QUAD_CurrentVersionRun_c37d {
  strings:
    $key_c37d = { 90 12 [2] b4 1c [2] 9f 30 [2] b1 12 [2] a5 09 [2] aa 13 [2] b4 0e [2] b6 0f [2] ad 09 [2] b1 0e [2] ad 21 }

  condition:
    any of them
}