rule TTP_XOR_WriteProcessMemory_67ec {
  strings:
    $key_67ec = { 30 9e [2] 02 bc [2] 04 89 [2] 2a 89 [2] 15 95 }

  condition:
    any of them
}