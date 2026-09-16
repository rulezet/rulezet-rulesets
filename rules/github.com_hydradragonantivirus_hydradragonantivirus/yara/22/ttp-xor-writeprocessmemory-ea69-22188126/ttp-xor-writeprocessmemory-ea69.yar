rule TTP_XOR_WriteProcessMemory_ea69 {
  strings:
    $key_ea69 = { bd 1b [2] 8f 39 [2] 89 0c [2] a7 0c [2] 98 10 }

  condition:
    any of them
}