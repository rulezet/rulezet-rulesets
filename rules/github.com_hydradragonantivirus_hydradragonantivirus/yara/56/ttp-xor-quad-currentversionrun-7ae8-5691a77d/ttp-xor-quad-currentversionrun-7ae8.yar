rule TTP_XOR_QUAD_CurrentVersionRun_7ae8 {
  strings:
    $key_7ae8 = { 29 87 [2] 0d 89 [2] 26 a5 [2] 08 87 [2] 1c 9c [2] 13 86 [2] 0d 9b [2] 0f 9a [2] 14 9c [2] 08 9b [2] 14 b4 }

  condition:
    any of them
}