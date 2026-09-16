rule TTP_XOR_WriteProcessMemory_d985 {
  strings:
    $key_d985 = { 8e f7 [2] bc d5 [2] ba e0 [2] 94 e0 [2] ab fc }

  condition:
    any of them
}