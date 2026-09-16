rule TTP_XOR_QUAD_CurrentVersionRun_c32d {
  strings:
    $key_c32d = { 90 42 [2] b4 4c [2] 9f 60 [2] b1 42 [2] a5 59 [2] aa 43 [2] b4 5e [2] b6 5f [2] ad 59 [2] b1 5e [2] ad 71 }

  condition:
    any of them
}