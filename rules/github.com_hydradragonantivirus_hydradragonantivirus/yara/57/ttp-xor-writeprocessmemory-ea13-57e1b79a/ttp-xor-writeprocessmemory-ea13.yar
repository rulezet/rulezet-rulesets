rule TTP_XOR_WriteProcessMemory_ea13 {
  strings:
    $key_ea13 = { bd 61 [2] 8f 43 [2] 89 76 [2] a7 76 [2] 98 6a }

  condition:
    any of them
}