rule TTP_XOR_WriteProcessMemory_04ec {
  strings:
    $key_04ec = { 53 9e [2] 61 bc [2] 67 89 [2] 49 89 [2] 76 95 }

  condition:
    any of them
}