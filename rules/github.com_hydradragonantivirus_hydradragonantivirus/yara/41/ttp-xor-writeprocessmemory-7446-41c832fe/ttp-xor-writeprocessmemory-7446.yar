rule TTP_XOR_WriteProcessMemory_7446 {
  strings:
    $key_7446 = { 23 34 [2] 11 16 [2] 17 23 [2] 39 23 [2] 06 3f }

  condition:
    any of them
}