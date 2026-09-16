rule TTP_XOR_WriteProcessMemory_5fec {
  strings:
    $key_5fec = { 08 9e [2] 3a bc [2] 3c 89 [2] 12 89 [2] 2d 95 }

  condition:
    any of them
}