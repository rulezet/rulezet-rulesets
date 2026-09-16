rule TTP_XOR_QUAD_CurrentVersionRun_f604 {
  strings:
    $key_f604 = { a5 6b [2] 81 65 [2] aa 49 [2] 84 6b [2] 90 70 [2] 9f 6a [2] 81 77 [2] 83 76 [2] 98 70 [2] 84 77 [2] 98 58 }

  condition:
    any of them
}