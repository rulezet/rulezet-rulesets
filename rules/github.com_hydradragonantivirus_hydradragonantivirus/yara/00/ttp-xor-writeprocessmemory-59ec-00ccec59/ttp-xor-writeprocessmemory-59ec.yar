rule TTP_XOR_WriteProcessMemory_59ec {
  strings:
    $key_59ec = { 0e 9e [2] 3c bc [2] 3a 89 [2] 14 89 [2] 2b 95 }

  condition:
    any of them
}