rule TTP_XOR_QUAD_CurrentVersionRun_f644 {
  strings:
    $key_f644 = { a5 2b [2] 81 25 [2] aa 09 [2] 84 2b [2] 90 30 [2] 9f 2a [2] 81 37 [2] 83 36 [2] 98 30 [2] 84 37 [2] 98 18 }

  condition:
    any of them
}