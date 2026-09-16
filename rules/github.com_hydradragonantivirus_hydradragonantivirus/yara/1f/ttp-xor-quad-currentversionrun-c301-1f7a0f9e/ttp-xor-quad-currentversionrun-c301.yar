rule TTP_XOR_QUAD_CurrentVersionRun_c301 {
  strings:
    $key_c301 = { 90 6e [2] b4 60 [2] 9f 4c [2] b1 6e [2] a5 75 [2] aa 6f [2] b4 72 [2] b6 73 [2] ad 75 [2] b1 72 [2] ad 5d }

  condition:
    any of them
}