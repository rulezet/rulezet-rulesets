rule TTP_XOR_WriteProcessMemory_ea01 {
  strings:
    $key_ea01 = { bd 73 [2] 8f 51 [2] 89 64 [2] a7 64 [2] 98 78 }

  condition:
    any of them
}