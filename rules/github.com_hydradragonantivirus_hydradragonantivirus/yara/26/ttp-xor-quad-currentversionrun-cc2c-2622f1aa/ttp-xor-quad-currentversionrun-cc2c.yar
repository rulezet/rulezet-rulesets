rule TTP_XOR_QUAD_CurrentVersionRun_cc2c {
  strings:
    $key_cc2c = { 9f 43 [2] bb 4d [2] 90 61 [2] be 43 [2] aa 58 [2] a5 42 [2] bb 5f [2] b9 5e [2] a2 58 [2] be 5f [2] a2 70 }

  condition:
    any of them
}