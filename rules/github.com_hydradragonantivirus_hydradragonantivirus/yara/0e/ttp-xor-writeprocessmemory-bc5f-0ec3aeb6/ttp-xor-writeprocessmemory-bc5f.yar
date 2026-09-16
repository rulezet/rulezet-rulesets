rule TTP_XOR_WriteProcessMemory_bc5f {
  strings:
    $key_bc5f = { eb 2d [2] d9 0f [2] df 3a [2] f1 3a [2] ce 26 }

  condition:
    any of them
}