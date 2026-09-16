rule TTP_XOR_WriteProcessMemory_53dc {
  strings:
    $key_53dc = { 04 ae [2] 36 8c [2] 30 b9 [2] 1e b9 [2] 21 a5 }

  condition:
    any of them
}