rule TTP_XOR_WriteProcessMemory_e8ec {
  strings:
    $key_e8ec = { bf 9e [2] 8d bc [2] 8b 89 [2] a5 89 [2] 9a 95 }

  condition:
    any of them
}