rule TTP_XOR_QUAD_CurrentVersionRun_f639 {
  strings:
    $key_f639 = { a5 56 [2] 81 58 [2] aa 74 [2] 84 56 [2] 90 4d [2] 9f 57 [2] 81 4a [2] 83 4b [2] 98 4d [2] 84 4a [2] 98 65 }

  condition:
    any of them
}