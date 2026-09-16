rule TTP_XOR_WriteProcessMemory_73dc {
  strings:
    $key_73dc = { 24 ae [2] 16 8c [2] 10 b9 [2] 3e b9 [2] 01 a5 }

  condition:
    any of them
}