rule TTP_XOR_WriteProcessMemory_f3ec {
  strings:
    $key_f3ec = { a4 9e [2] 96 bc [2] 90 89 [2] be 89 [2] 81 95 }

  condition:
    any of them
}