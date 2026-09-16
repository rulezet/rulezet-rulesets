rule TTP_XOR_QUAD_CurrentVersionRun_1678 {
  strings:
    $key_1678 = { 45 17 [2] 61 19 [2] 4a 35 [2] 64 17 [2] 70 0c [2] 7f 16 [2] 61 0b [2] 63 0a [2] 78 0c [2] 64 0b [2] 78 24 }

  condition:
    any of them
}