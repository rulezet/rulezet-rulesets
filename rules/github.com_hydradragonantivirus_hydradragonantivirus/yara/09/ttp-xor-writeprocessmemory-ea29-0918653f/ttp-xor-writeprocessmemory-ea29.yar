rule TTP_XOR_WriteProcessMemory_ea29 {
  strings:
    $key_ea29 = { bd 5b [2] 8f 79 [2] 89 4c [2] a7 4c [2] 98 50 }

  condition:
    any of them
}