rule TTP_XOR_WriteProcessMemory_3e66 {
  strings:
    $key_3e66 = { 69 14 [2] 5b 36 [2] 5d 03 [2] 73 03 [2] 4c 1f }

  condition:
    any of them
}