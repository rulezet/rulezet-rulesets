rule TTP_XOR_QUAD_CurrentVersionRun_1665 {
  strings:
    $key_1665 = { 45 0a [2] 61 04 [2] 4a 28 [2] 64 0a [2] 70 11 [2] 7f 0b [2] 61 16 [2] 63 17 [2] 78 11 [2] 64 16 [2] 78 39 }

  condition:
    any of them
}