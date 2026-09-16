rule TTP_XOR_WriteProcessMemory_bcb9 {
  strings:
    $key_bcb9 = { eb cb [2] d9 e9 [2] df dc [2] f1 dc [2] ce c0 }

  condition:
    any of them
}