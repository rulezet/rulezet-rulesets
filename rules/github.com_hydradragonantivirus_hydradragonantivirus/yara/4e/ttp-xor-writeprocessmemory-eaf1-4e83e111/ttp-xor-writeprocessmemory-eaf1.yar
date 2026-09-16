rule TTP_XOR_WriteProcessMemory_eaf1 {
  strings:
    $key_eaf1 = { bd 83 [2] 8f a1 [2] 89 94 [2] a7 94 [2] 98 88 }

  condition:
    any of them
}