rule TTP_XOR_QUAD_CurrentVersionRun_f104 {
  strings:
    $key_f104 = { a2 6b [2] 86 65 [2] ad 49 [2] 83 6b [2] 97 70 [2] 98 6a [2] 86 77 [2] 84 76 [2] 9f 70 [2] 83 77 [2] 9f 58 }

  condition:
    any of them
}