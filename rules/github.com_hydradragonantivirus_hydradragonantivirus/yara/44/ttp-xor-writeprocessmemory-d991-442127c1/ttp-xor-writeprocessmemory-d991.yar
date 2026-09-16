rule TTP_XOR_WriteProcessMemory_d991 {
  strings:
    $key_d991 = { 8e e3 [2] bc c1 [2] ba f4 [2] 94 f4 [2] ab e8 }

  condition:
    any of them
}