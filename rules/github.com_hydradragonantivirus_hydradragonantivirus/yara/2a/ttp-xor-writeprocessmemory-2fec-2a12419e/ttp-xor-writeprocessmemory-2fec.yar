rule TTP_XOR_WriteProcessMemory_2fec {
  strings:
    $key_2fec = { 78 9e [2] 4a bc [2] 4c 89 [2] 62 89 [2] 5d 95 }

  condition:
    any of them
}