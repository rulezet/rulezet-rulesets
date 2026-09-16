rule TTP_XOR_WriteProcessMemory_ea59 {
  strings:
    $key_ea59 = { bd 2b [2] 8f 09 [2] 89 3c [2] a7 3c [2] 98 20 }

  condition:
    any of them
}