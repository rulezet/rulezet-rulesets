rule TTP_XOR_WriteProcessMemory_56ec {
  strings:
    $key_56ec = { 01 9e [2] 33 bc [2] 35 89 [2] 1b 89 [2] 24 95 }

  condition:
    any of them
}