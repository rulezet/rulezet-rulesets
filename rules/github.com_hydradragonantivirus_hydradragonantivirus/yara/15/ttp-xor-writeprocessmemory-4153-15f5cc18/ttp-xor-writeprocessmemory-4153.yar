rule TTP_XOR_WriteProcessMemory_4153 {
  strings:
    $key_4153 = { 16 21 [2] 24 03 [2] 22 36 [2] 0c 36 [2] 33 2a }

  condition:
    any of them
}