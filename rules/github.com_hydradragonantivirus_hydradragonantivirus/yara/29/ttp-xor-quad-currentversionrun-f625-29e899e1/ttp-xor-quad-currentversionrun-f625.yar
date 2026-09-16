rule TTP_XOR_QUAD_CurrentVersionRun_f625 {
  strings:
    $key_f625 = { a5 4a [2] 81 44 [2] aa 68 [2] 84 4a [2] 90 51 [2] 9f 4b [2] 81 56 [2] 83 57 [2] 98 51 [2] 84 56 [2] 98 79 }

  condition:
    any of them
}