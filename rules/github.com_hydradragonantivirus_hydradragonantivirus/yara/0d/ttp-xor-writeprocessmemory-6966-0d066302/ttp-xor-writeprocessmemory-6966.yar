rule TTP_XOR_WriteProcessMemory_6966 {
  strings:
    $key_6966 = { 3e 14 [2] 0c 36 [2] 0a 03 [2] 24 03 [2] 1b 1f }

  condition:
    any of them
}