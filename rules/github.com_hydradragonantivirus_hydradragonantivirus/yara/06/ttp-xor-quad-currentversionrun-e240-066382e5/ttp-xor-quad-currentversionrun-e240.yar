rule TTP_XOR_QUAD_CurrentVersionRun_e240 {
  strings:
    $key_e240 = { b1 2f [2] 95 21 [2] be 0d [2] 90 2f [2] 84 34 [2] 8b 2e [2] 95 33 [2] 97 32 [2] 8c 34 [2] 90 33 [2] 8c 1c }

  condition:
    any of them
}