rule TTP_XOR_WriteProcessMemory_ea17 {
  strings:
    $key_ea17 = { bd 65 [2] 8f 47 [2] 89 72 [2] a7 72 [2] 98 6e }

  condition:
    any of them
}