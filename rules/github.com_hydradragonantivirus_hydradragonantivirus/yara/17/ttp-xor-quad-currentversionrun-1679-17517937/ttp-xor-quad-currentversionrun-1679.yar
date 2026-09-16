rule TTP_XOR_QUAD_CurrentVersionRun_1679 {
  strings:
    $key_1679 = { 45 16 [2] 61 18 [2] 4a 34 [2] 64 16 [2] 70 0d [2] 7f 17 [2] 61 0a [2] 63 0b [2] 78 0d [2] 64 0a [2] 78 25 }

  condition:
    any of them
}