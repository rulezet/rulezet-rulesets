rule TTP_XOR_WriteProcessMemory_5306 {
  strings:
    $key_5306 = { 04 74 [2] 36 56 [2] 30 63 [2] 1e 63 [2] 21 7f }

  condition:
    any of them
}