rule TTP_XOR_WriteProcessMemory_d997 {
  strings:
    $key_d997 = { 8e e5 [2] bc c7 [2] ba f2 [2] 94 f2 [2] ab ee }

  condition:
    any of them
}