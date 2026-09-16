rule TTP_XOR_WriteProcessMemory_eaf9 {
  strings:
    $key_eaf9 = { bd 8b [2] 8f a9 [2] 89 9c [2] a7 9c [2] 98 80 }

  condition:
    any of them
}