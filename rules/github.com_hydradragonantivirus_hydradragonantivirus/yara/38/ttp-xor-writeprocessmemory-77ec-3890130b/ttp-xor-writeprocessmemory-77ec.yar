rule TTP_XOR_WriteProcessMemory_77ec {
  strings:
    $key_77ec = { 20 9e [2] 12 bc [2] 14 89 [2] 3a 89 [2] 05 95 }

  condition:
    any of them
}