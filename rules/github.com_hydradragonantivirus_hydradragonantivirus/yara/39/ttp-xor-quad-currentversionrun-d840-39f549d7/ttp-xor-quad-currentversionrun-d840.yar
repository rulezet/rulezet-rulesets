rule TTP_XOR_QUAD_CurrentVersionRun_d840 {
  strings:
    $key_d840 = { 8b 2f [2] af 21 [2] 84 0d [2] aa 2f [2] be 34 [2] b1 2e [2] af 33 [2] ad 32 [2] b6 34 [2] aa 33 [2] b6 1c }

  condition:
    any of them
}