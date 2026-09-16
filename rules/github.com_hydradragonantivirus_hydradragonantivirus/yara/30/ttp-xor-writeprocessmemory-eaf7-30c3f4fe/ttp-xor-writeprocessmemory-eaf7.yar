rule TTP_XOR_WriteProcessMemory_eaf7 {
  strings:
    $key_eaf7 = { bd 85 [2] 8f a7 [2] 89 92 [2] a7 92 [2] 98 8e }

  condition:
    any of them
}