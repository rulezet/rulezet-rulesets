rule TTP_XOR_WriteProcessMemory_ea4c {
  strings:
    $key_ea4c = { bd 3e [2] 8f 1c [2] 89 29 [2] a7 29 [2] 98 35 }

  condition:
    any of them
}