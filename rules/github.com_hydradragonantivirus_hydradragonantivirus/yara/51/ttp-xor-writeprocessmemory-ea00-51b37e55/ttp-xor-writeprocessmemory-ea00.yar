rule TTP_XOR_WriteProcessMemory_ea00 {
  strings:
    $key_ea00 = { bd 72 [2] 8f 50 [2] 89 65 [2] a7 65 [2] 98 79 }

  condition:
    any of them
}