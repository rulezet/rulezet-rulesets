rule TTP_XOR_QUAD_CurrentVersionRun_f12b {
  strings:
    $key_f12b = { a2 44 [2] 86 4a [2] ad 66 [2] 83 44 [2] 97 5f [2] 98 45 [2] 86 58 [2] 84 59 [2] 9f 5f [2] 83 58 [2] 9f 77 }

  condition:
    any of them
}