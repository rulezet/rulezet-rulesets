rule TTP_XOR_WriteProcessMemory_30ec {
  strings:
    $key_30ec = { 67 9e [2] 55 bc [2] 53 89 [2] 7d 89 [2] 42 95 }

  condition:
    any of them
}