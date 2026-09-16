rule TTP_XOR_WriteProcessMemory_ea43 {
  strings:
    $key_ea43 = { bd 31 [2] 8f 13 [2] 89 26 [2] a7 26 [2] 98 3a }

  condition:
    any of them
}