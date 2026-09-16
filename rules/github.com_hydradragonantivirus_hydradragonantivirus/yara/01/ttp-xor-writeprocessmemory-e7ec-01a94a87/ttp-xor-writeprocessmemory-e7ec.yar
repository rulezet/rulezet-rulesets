rule TTP_XOR_WriteProcessMemory_e7ec {
  strings:
    $key_e7ec = { b0 9e [2] 82 bc [2] 84 89 [2] aa 89 [2] 95 95 }

  condition:
    any of them
}