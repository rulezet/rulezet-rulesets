rule TTP_XOR_QUAD_CurrentVersionRun_f129 {
  strings:
    $key_f129 = { a2 46 [2] 86 48 [2] ad 64 [2] 83 46 [2] 97 5d [2] 98 47 [2] 86 5a [2] 84 5b [2] 9f 5d [2] 83 5a [2] 9f 75 }

  condition:
    any of them
}