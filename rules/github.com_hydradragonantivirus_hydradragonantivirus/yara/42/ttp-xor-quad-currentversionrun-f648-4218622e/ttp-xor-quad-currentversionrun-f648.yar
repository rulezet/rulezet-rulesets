rule TTP_XOR_QUAD_CurrentVersionRun_f648 {
  strings:
    $key_f648 = { a5 27 [2] 81 29 [2] aa 05 [2] 84 27 [2] 90 3c [2] 9f 26 [2] 81 3b [2] 83 3a [2] 98 3c [2] 84 3b [2] 98 14 }

  condition:
    any of them
}