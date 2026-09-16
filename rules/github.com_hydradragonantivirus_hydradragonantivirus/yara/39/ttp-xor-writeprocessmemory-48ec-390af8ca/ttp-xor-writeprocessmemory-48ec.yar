rule TTP_XOR_WriteProcessMemory_48ec {
  strings:
    $key_48ec = { 1f 9e [2] 2d bc [2] 2b 89 [2] 05 89 [2] 3a 95 }

  condition:
    any of them
}