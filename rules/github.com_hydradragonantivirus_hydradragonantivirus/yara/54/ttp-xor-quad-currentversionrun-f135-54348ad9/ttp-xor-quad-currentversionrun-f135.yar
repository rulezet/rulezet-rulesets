rule TTP_XOR_QUAD_CurrentVersionRun_f135 {
  strings:
    $key_f135 = { a2 5a [2] 86 54 [2] ad 78 [2] 83 5a [2] 97 41 [2] 98 5b [2] 86 46 [2] 84 47 [2] 9f 41 [2] 83 46 [2] 9f 69 }

  condition:
    any of them
}