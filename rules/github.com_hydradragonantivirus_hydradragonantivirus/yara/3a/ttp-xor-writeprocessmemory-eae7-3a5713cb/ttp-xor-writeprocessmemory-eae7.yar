rule TTP_XOR_WriteProcessMemory_eae7 {
  strings:
    $key_eae7 = { bd 95 [2] 8f b7 [2] 89 82 [2] a7 82 [2] 98 9e }

  condition:
    any of them
}