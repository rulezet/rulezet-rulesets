rule TTP_XOR_QUAD_CurrentVersionRun_3ff4 {
  strings:
    $key_3ff4 = { 6c 9b [2] 48 95 [2] 63 b9 [2] 4d 9b [2] 59 80 [2] 56 9a [2] 48 87 [2] 4a 86 [2] 51 80 [2] 4d 87 [2] 51 a8 }

  condition:
    any of them
}