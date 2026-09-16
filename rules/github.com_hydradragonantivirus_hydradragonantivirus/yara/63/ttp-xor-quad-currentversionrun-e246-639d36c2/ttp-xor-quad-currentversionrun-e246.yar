rule TTP_XOR_QUAD_CurrentVersionRun_e246 {
  strings:
    $key_e246 = { b1 29 [2] 95 27 [2] be 0b [2] 90 29 [2] 84 32 [2] 8b 28 [2] 95 35 [2] 97 34 [2] 8c 32 [2] 90 35 [2] 8c 1a }

  condition:
    any of them
}