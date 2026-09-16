rule TTP_XOR_WriteProcessMemory_ea72 {
  strings:
    $key_ea72 = { bd 00 [2] 8f 22 [2] 89 17 [2] a7 17 [2] 98 0b }

  condition:
    any of them
}