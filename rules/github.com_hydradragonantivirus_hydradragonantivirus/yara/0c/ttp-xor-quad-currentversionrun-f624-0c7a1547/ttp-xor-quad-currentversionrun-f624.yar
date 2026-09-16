rule TTP_XOR_QUAD_CurrentVersionRun_f624 {
  strings:
    $key_f624 = { a5 4b [2] 81 45 [2] aa 69 [2] 84 4b [2] 90 50 [2] 9f 4a [2] 81 57 [2] 83 56 [2] 98 50 [2] 84 57 [2] 98 78 }

  condition:
    any of them
}