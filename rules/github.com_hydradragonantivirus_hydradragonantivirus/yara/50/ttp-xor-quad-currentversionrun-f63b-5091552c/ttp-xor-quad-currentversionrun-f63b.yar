rule TTP_XOR_QUAD_CurrentVersionRun_f63b {
  strings:
    $key_f63b = { a5 54 [2] 81 5a [2] aa 76 [2] 84 54 [2] 90 4f [2] 9f 55 [2] 81 48 [2] 83 49 [2] 98 4f [2] 84 48 [2] 98 67 }

  condition:
    any of them
}