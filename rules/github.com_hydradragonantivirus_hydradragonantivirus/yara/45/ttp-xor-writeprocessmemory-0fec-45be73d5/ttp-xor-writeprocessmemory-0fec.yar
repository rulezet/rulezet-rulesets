rule TTP_XOR_WriteProcessMemory_0fec {
  strings:
    $key_0fec = { 58 9e [2] 6a bc [2] 6c 89 [2] 42 89 [2] 7d 95 }

  condition:
    any of them
}