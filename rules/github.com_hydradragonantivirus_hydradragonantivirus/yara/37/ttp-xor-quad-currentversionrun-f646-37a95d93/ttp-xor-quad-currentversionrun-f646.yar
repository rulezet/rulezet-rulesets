rule TTP_XOR_QUAD_CurrentVersionRun_f646 {
  strings:
    $key_f646 = { a5 29 [2] 81 27 [2] aa 0b [2] 84 29 [2] 90 32 [2] 9f 28 [2] 81 35 [2] 83 34 [2] 98 32 [2] 84 35 [2] 98 1a }

  condition:
    any of them
}