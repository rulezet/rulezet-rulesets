rule TTP_XOR_QUAD_CurrentVersionRun_1108 {
  strings:
    $key_1108 = { 42 67 [2] 66 69 [2] 4d 45 [2] 63 67 [2] 77 7c [2] 78 66 [2] 66 7b [2] 64 7a [2] 7f 7c [2] 63 7b [2] 7f 54 }

  condition:
    any of them
}