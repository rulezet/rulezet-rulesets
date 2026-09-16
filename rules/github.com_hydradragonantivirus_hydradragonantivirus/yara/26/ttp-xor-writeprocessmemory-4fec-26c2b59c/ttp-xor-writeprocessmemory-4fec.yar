rule TTP_XOR_WriteProcessMemory_4fec {
  strings:
    $key_4fec = { 18 9e [2] 2a bc [2] 2c 89 [2] 02 89 [2] 3d 95 }

  condition:
    any of them
}