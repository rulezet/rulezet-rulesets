rule TTP_XOR_WriteProcessMemory_ea08 {
  strings:
    $key_ea08 = { bd 7a [2] 8f 58 [2] 89 6d [2] a7 6d [2] 98 71 }

  condition:
    any of them
}