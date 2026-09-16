rule TTP_XOR_QUAD_CurrentVersionRun_11e8 {
  strings:
    $key_11e8 = { 42 87 [2] 66 89 [2] 4d a5 [2] 63 87 [2] 77 9c [2] 78 86 [2] 66 9b [2] 64 9a [2] 7f 9c [2] 63 9b [2] 7f b4 }

  condition:
    any of them
}