rule TTP_XOR_WriteProcessMemory_ea41 {
  strings:
    $key_ea41 = { bd 33 [2] 8f 11 [2] 89 24 [2] a7 24 [2] 98 38 }

  condition:
    any of them
}