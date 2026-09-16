rule TTP_XOR_WriteProcessMemory_3bec {
  strings:
    $key_3bec = { 6c 9e [2] 5e bc [2] 58 89 [2] 76 89 [2] 49 95 }

  condition:
    any of them
}