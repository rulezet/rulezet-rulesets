rule TTP_XOR_WriteProcessMemory_08ec {
  strings:
    $key_08ec = { 5f 9e [2] 6d bc [2] 6b 89 [2] 45 89 [2] 7a 95 }

  condition:
    any of them
}