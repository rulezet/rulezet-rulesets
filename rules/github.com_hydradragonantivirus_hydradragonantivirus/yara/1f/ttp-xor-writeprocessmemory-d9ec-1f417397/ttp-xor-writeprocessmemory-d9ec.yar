rule TTP_XOR_WriteProcessMemory_d9ec {
  strings:
    $key_d9ec = { 8e 9e [2] bc bc [2] ba 89 [2] 94 89 [2] ab 95 }

  condition:
    any of them
}