rule TTP_XOR_QUAD_CurrentVersionRun_f108 {
  strings:
    $key_f108 = { a2 67 [2] 86 69 [2] ad 45 [2] 83 67 [2] 97 7c [2] 98 66 [2] 86 7b [2] 84 7a [2] 9f 7c [2] 83 7b [2] 9f 54 }

  condition:
    any of them
}