rule TTP_XOR_WriteProcessMemory_e0ec {
  strings:
    $key_e0ec = { b7 9e [2] 85 bc [2] 83 89 [2] ad 89 [2] 92 95 }

  condition:
    any of them
}