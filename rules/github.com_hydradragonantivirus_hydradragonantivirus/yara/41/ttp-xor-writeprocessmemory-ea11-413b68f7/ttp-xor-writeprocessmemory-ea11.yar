rule TTP_XOR_WriteProcessMemory_ea11 {
  strings:
    $key_ea11 = { bd 63 [2] 8f 41 [2] 89 74 [2] a7 74 [2] 98 68 }

  condition:
    any of them
}