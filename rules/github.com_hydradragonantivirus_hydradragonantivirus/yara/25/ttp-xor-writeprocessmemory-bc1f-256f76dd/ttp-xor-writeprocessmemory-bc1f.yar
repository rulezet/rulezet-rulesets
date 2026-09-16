rule TTP_XOR_WriteProcessMemory_bc1f {
  strings:
    $key_bc1f = { eb 6d [2] d9 4f [2] df 7a [2] f1 7a [2] ce 66 }

  condition:
    any of them
}