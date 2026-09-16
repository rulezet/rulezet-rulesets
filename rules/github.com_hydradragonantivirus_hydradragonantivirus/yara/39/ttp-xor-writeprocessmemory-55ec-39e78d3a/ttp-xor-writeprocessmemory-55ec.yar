rule TTP_XOR_WriteProcessMemory_55ec {
  strings:
    $key_55ec = { 02 9e [2] 30 bc [2] 36 89 [2] 18 89 [2] 27 95 }

  condition:
    any of them
}