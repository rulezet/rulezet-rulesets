rule TTP_XOR_WriteProcessMemory_69ec {
  strings:
    $key_69ec = { 3e 9e [2] 0c bc [2] 0a 89 [2] 24 89 [2] 1b 95 }

  condition:
    any of them
}