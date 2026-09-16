rule TTP_XOR_WriteProcessMemory_35ec {
  strings:
    $key_35ec = { 62 9e [2] 50 bc [2] 56 89 [2] 78 89 [2] 47 95 }

  condition:
    any of them
}