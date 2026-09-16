rule TTP_XOR_WriteProcessMemory_bc58 {
  strings:
    $key_bc58 = { eb 2a [2] d9 08 [2] df 3d [2] f1 3d [2] ce 21 }

  condition:
    any of them
}