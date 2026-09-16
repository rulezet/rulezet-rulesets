rule TTP_XOR_WriteProcessMemory_bc28 {
  strings:
    $key_bc28 = { eb 5a [2] d9 78 [2] df 4d [2] f1 4d [2] ce 51 }

  condition:
    any of them
}