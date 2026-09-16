rule TTP_XOR_WriteProcessMemory_ea52 {
  strings:
    $key_ea52 = { bd 20 [2] 8f 02 [2] 89 37 [2] a7 37 [2] 98 2b }

  condition:
    any of them
}