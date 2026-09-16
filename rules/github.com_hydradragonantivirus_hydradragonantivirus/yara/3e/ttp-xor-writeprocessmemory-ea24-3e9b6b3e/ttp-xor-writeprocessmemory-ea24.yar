rule TTP_XOR_WriteProcessMemory_ea24 {
  strings:
    $key_ea24 = { bd 56 [2] 8f 74 [2] 89 41 [2] a7 41 [2] 98 5d }

  condition:
    any of them
}