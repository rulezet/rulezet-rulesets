rule TTP_XOR_WriteProcessMemory_7fec {
  strings:
    $key_7fec = { 28 9e [2] 1a bc [2] 1c 89 [2] 32 89 [2] 0d 95 }

  condition:
    any of them
}