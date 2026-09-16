rule TTP_XOR_WriteProcessMemory_8cfe {
  strings:
    $key_8cfe = { db 8c [2] e9 ae [2] ef 9b [2] c1 9b [2] fe 87 }

  condition:
    any of them
}