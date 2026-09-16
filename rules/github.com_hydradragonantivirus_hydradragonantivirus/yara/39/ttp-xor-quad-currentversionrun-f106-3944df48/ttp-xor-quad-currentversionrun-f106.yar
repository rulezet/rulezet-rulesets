rule TTP_XOR_QUAD_CurrentVersionRun_f106 {
  strings:
    $key_f106 = { a2 69 [2] 86 67 [2] ad 4b [2] 83 69 [2] 97 72 [2] 98 68 [2] 86 75 [2] 84 74 [2] 9f 72 [2] 83 75 [2] 9f 5a }

  condition:
    any of them
}