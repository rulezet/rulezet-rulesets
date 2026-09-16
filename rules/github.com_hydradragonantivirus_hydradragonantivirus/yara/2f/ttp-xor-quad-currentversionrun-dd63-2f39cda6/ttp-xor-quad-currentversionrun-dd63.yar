rule TTP_XOR_QUAD_CurrentVersionRun_dd63 {
  strings:
    $key_dd63 = { 8e 0c [2] aa 02 [2] 81 2e [2] af 0c [2] bb 17 [2] b4 0d [2] aa 10 [2] a8 11 [2] b3 17 [2] af 10 [2] b3 3f }

  condition:
    any of them
}