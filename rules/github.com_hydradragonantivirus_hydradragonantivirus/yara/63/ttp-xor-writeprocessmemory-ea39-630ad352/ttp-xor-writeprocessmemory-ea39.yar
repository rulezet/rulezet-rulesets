rule TTP_XOR_WriteProcessMemory_ea39 {
  strings:
    $key_ea39 = { bd 4b [2] 8f 69 [2] 89 5c [2] a7 5c [2] 98 40 }

  condition:
    any of them
}