rule TTP_XOR_WriteProcessMemory_bc3d {
  strings:
    $key_bc3d = { eb 4f [2] d9 6d [2] df 58 [2] f1 58 [2] ce 44 }

  condition:
    any of them
}