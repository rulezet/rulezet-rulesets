rule TTP_XOR_WriteProcessMemory_ea68 {
  strings:
    $key_ea68 = { bd 1a [2] 8f 38 [2] 89 0d [2] a7 0d [2] 98 11 }

  condition:
    any of them
}