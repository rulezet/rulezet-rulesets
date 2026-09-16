rule TTP_XOR_QUAD_CurrentVersionRun_f636 {
  strings:
    $key_f636 = { a5 59 [2] 81 57 [2] aa 7b [2] 84 59 [2] 90 42 [2] 9f 58 [2] 81 45 [2] 83 44 [2] 98 42 [2] 84 45 [2] 98 6a }

  condition:
    any of them
}