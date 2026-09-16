rule TTP_XOR_WriteProcessMemory_8c09 {
  strings:
    $key_8c09 = { db 7b [2] e9 59 [2] ef 6c [2] c1 6c [2] fe 70 }

  condition:
    any of them
}