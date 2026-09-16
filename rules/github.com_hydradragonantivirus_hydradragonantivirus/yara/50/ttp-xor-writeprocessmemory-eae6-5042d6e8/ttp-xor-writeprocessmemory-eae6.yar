rule TTP_XOR_WriteProcessMemory_eae6 {
  strings:
    $key_eae6 = { bd 94 [2] 8f b6 [2] 89 83 [2] a7 83 [2] 98 9f }

  condition:
    any of them
}