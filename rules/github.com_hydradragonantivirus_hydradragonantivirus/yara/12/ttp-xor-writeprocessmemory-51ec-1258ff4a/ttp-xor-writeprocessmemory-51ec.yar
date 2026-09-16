rule TTP_XOR_WriteProcessMemory_51ec {
  strings:
    $key_51ec = { 06 9e [2] 34 bc [2] 32 89 [2] 1c 89 [2] 23 95 }

  condition:
    any of them
}