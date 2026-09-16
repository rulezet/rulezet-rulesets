rule TTP_XOR_WriteProcessMemory_ea2c {
  strings:
    $key_ea2c = { bd 5e [2] 8f 7c [2] 89 49 [2] a7 49 [2] 98 55 }

  condition:
    any of them
}