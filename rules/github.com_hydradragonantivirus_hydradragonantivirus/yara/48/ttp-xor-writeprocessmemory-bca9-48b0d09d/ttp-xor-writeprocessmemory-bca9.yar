rule TTP_XOR_WriteProcessMemory_bca9 {
  strings:
    $key_bca9 = { eb db [2] d9 f9 [2] df cc [2] f1 cc [2] ce d0 }

  condition:
    any of them
}