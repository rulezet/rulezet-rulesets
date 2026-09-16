rule TTP_XOR_WriteProcessMemory_e9ec {
  strings:
    $key_e9ec = { be 9e [2] 8c bc [2] 8a 89 [2] a4 89 [2] 9b 95 }

  condition:
    any of them
}