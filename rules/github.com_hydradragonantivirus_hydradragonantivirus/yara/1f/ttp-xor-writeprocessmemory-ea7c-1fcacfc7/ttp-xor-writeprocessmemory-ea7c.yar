rule TTP_XOR_WriteProcessMemory_ea7c {
  strings:
    $key_ea7c = { bd 0e [2] 8f 2c [2] 89 19 [2] a7 19 [2] 98 05 }

  condition:
    any of them
}