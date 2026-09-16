rule TTP_XOR_QUAD_CurrentVersionRun_f1e8 {
  strings:
    $key_f1e8 = { a2 87 [2] 86 89 [2] ad a5 [2] 83 87 [2] 97 9c [2] 98 86 [2] 86 9b [2] 84 9a [2] 9f 9c [2] 83 9b [2] 9f b4 }

  condition:
    any of them
}