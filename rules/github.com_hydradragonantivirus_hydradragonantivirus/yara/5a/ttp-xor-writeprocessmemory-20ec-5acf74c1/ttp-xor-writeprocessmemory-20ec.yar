rule TTP_XOR_WriteProcessMemory_20ec {
  strings:
    $key_20ec = { 77 9e [2] 45 bc [2] 43 89 [2] 6d 89 [2] 52 95 }

  condition:
    any of them
}