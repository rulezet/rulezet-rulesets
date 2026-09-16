rule TTP_XOR_WriteProcessMemory_eae9 {
  strings:
    $key_eae9 = { bd 9b [2] 8f b9 [2] 89 8c [2] a7 8c [2] 98 90 }

  condition:
    any of them
}