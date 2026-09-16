rule TTP_XOR_WriteProcessMemory_37ec {
  strings:
    $key_37ec = { 60 9e [2] 52 bc [2] 54 89 [2] 7a 89 [2] 45 95 }

  condition:
    any of them
}