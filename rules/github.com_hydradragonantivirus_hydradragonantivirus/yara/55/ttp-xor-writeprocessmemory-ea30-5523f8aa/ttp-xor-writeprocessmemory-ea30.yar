rule TTP_XOR_WriteProcessMemory_ea30 {
  strings:
    $key_ea30 = { bd 42 [2] 8f 60 [2] 89 55 [2] a7 55 [2] 98 49 }

  condition:
    any of them
}