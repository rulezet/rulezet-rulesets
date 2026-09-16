rule TTP_XOR_WriteProcessMemory_bc6f {
  strings:
    $key_bc6f = { eb 1d [2] d9 3f [2] df 0a [2] f1 0a [2] ce 16 }

  condition:
    any of them
}