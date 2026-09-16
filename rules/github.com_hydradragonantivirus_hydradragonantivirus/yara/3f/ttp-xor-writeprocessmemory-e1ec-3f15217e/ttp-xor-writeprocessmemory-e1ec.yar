rule TTP_XOR_WriteProcessMemory_e1ec {
  strings:
    $key_e1ec = { b6 9e [2] 84 bc [2] 82 89 [2] ac 89 [2] 93 95 }

  condition:
    any of them
}