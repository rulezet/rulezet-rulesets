rule TTP_XOR_QUAD_CurrentVersionRun_51e8 {
  strings:
    $key_51e8 = { 02 87 [2] 26 89 [2] 0d a5 [2] 23 87 [2] 37 9c [2] 38 86 [2] 26 9b [2] 24 9a [2] 3f 9c [2] 23 9b [2] 3f b4 }

  condition:
    any of them
}