rule TTP_XOR_WriteProcessMemory_f188 {
  strings:
    $key_f188 = { a6 fa [2] 94 d8 [2] 92 ed [2] bc ed [2] 83 f1 }

  condition:
    any of them
}