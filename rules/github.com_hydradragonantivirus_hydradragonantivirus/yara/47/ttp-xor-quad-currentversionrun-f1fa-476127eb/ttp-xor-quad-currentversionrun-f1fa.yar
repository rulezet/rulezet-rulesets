rule TTP_XOR_QUAD_CurrentVersionRun_f1fa {
  strings:
    $key_f1fa = { a2 95 [2] 86 9b [2] ad b7 [2] 83 95 [2] 97 8e [2] 98 94 [2] 86 89 [2] 84 88 [2] 9f 8e [2] 83 89 [2] 9f a6 }

  condition:
    any of them
}