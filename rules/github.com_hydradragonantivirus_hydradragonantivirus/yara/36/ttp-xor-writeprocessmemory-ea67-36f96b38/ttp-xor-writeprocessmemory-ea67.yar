rule TTP_XOR_WriteProcessMemory_ea67 {
  strings:
    $key_ea67 = { bd 15 [2] 8f 37 [2] 89 02 [2] a7 02 [2] 98 1e }

  condition:
    any of them
}