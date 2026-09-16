rule TTP_XOR_WriteProcessMemory_3e46 {
  strings:
    $key_3e46 = { 69 34 [2] 5b 16 [2] 5d 23 [2] 73 23 [2] 4c 3f }

  condition:
    any of them
}