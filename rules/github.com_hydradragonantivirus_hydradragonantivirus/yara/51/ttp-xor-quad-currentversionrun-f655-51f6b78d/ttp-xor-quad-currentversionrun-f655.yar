rule TTP_XOR_QUAD_CurrentVersionRun_f655 {
  strings:
    $key_f655 = { a5 3a [2] 81 34 [2] aa 18 [2] 84 3a [2] 90 21 [2] 9f 3b [2] 81 26 [2] 83 27 [2] 98 21 [2] 84 26 [2] 98 09 }

  condition:
    any of them
}