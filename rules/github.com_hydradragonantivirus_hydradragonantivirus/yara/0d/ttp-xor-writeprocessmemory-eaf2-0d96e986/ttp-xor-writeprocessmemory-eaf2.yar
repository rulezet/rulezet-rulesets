rule TTP_XOR_WriteProcessMemory_eaf2 {
  strings:
    $key_eaf2 = { bd 80 [2] 8f a2 [2] 89 97 [2] a7 97 [2] 98 8b }

  condition:
    any of them
}