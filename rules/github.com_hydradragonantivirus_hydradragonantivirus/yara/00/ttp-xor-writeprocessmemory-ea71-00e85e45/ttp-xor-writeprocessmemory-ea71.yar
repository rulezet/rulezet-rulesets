rule TTP_XOR_WriteProcessMemory_ea71 {
  strings:
    $key_ea71 = { bd 03 [2] 8f 21 [2] 89 14 [2] a7 14 [2] 98 08 }

  condition:
    any of them
}