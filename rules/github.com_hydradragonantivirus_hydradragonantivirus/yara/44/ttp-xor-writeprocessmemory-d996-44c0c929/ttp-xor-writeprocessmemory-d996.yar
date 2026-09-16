rule TTP_XOR_WriteProcessMemory_d996 {
  strings:
    $key_d996 = { 8e e4 [2] bc c6 [2] ba f3 [2] 94 f3 [2] ab ef }

  condition:
    any of them
}