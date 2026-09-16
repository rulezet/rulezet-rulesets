rule TTP_XOR_WriteProcessMemory_ea32 {
  strings:
    $key_ea32 = { bd 40 [2] 8f 62 [2] 89 57 [2] a7 57 [2] 98 4b }

  condition:
    any of them
}