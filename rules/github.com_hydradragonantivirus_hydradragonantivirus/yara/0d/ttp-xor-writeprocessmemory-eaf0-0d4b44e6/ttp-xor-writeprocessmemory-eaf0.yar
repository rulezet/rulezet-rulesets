rule TTP_XOR_WriteProcessMemory_eaf0 {
  strings:
    $key_eaf0 = { bd 82 [2] 8f a0 [2] 89 95 [2] a7 95 [2] 98 89 }

  condition:
    any of them
}