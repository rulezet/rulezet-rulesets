rule TTP_XOR_WriteProcessMemory_12ec {
  strings:
    $key_12ec = { 45 9e [2] 77 bc [2] 71 89 [2] 5f 89 [2] 60 95 }

  condition:
    any of them
}