rule TTP_XOR_QUAD_CurrentVersionRun_c35b {
  strings:
    $key_c35b = { 90 34 [2] b4 3a [2] 9f 16 [2] b1 34 [2] a5 2f [2] aa 35 [2] b4 28 [2] b6 29 [2] ad 2f [2] b1 28 [2] ad 07 }

  condition:
    any of them
}