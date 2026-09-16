rule TTP_XOR_WriteProcessMemory_73ec {
  strings:
    $key_73ec = { 24 9e [2] 16 bc [2] 10 89 [2] 3e 89 [2] 01 95 }

  condition:
    any of them
}