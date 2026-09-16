rule TTP_XOR_WriteProcessMemory_8c69 {
  strings:
    $key_8c69 = { db 1b [2] e9 39 [2] ef 0c [2] c1 0c [2] fe 10 }

  condition:
    any of them
}