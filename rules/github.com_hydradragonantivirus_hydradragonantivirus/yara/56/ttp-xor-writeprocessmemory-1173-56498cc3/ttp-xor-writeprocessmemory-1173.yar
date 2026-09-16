rule TTP_XOR_WriteProcessMemory_1173 {
  strings:
    $key_1173 = { 46 01 [2] 74 23 [2] 72 16 [2] 5c 16 [2] 63 0a }

  condition:
    any of them
}