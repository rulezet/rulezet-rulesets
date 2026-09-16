rule TTP_XOR_WriteProcessMemory_eae1 {
  strings:
    $key_eae1 = { bd 93 [2] 8f b1 [2] 89 84 [2] a7 84 [2] 98 98 }

  condition:
    any of them
}