rule TTP_XOR_QUAD_CurrentVersionRun_f1f9 {
  strings:
    $key_f1f9 = { a2 96 [2] 86 98 [2] ad b4 [2] 83 96 [2] 97 8d [2] 98 97 [2] 86 8a [2] 84 8b [2] 9f 8d [2] 83 8a [2] 9f a5 }

  condition:
    any of them
}