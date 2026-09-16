rule TTP_XOR_QUAD_CurrentVersionRun_c313 {
  strings:
    $key_c313 = { 90 7c [2] b4 72 [2] 9f 5e [2] b1 7c [2] a5 67 [2] aa 7d [2] b4 60 [2] b6 61 [2] ad 67 [2] b1 60 [2] ad 4f }

  condition:
    any of them
}