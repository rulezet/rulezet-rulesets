rule TTP_XOR_WriteProcessMemory_6fec {
  strings:
    $key_6fec = { 38 9e [2] 0a bc [2] 0c 89 [2] 22 89 [2] 1d 95 }

  condition:
    any of them
}