rule TTP_XOR_QUAD_CurrentVersionRun_3ff5 {
  strings:
    $key_3ff5 = { 6c 9a [2] 48 94 [2] 63 b8 [2] 4d 9a [2] 59 81 [2] 56 9b [2] 48 86 [2] 4a 87 [2] 51 81 [2] 4d 86 [2] 51 a9 }

  condition:
    any of them
}