rule TTP_XOR_WriteProcessMemory_ea1c {
  strings:
    $key_ea1c = { bd 6e [2] 8f 4c [2] 89 79 [2] a7 79 [2] 98 65 }

  condition:
    any of them
}