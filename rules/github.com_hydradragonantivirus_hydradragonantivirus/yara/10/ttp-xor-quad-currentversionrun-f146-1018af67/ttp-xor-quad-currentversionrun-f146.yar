rule TTP_XOR_QUAD_CurrentVersionRun_f146 {
  strings:
    $key_f146 = { a2 29 [2] 86 27 [2] ad 0b [2] 83 29 [2] 97 32 [2] 98 28 [2] 86 35 [2] 84 34 [2] 9f 32 [2] 83 35 [2] 9f 1a }

  condition:
    any of them
}