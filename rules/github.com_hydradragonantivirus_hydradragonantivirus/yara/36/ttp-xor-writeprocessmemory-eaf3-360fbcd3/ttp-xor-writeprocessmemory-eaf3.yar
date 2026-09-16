rule TTP_XOR_WriteProcessMemory_eaf3 {
  strings:
    $key_eaf3 = { bd 81 [2] 8f a3 [2] 89 96 [2] a7 96 [2] 98 8a }

  condition:
    any of them
}