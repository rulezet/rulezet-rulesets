rule TTP_XOR_QUAD_CurrentVersionRun_c35d {
  strings:
    $key_c35d = { 90 32 [2] b4 3c [2] 9f 10 [2] b1 32 [2] a5 29 [2] aa 33 [2] b4 2e [2] b6 2f [2] ad 29 [2] b1 2e [2] ad 01 }

  condition:
    any of them
}