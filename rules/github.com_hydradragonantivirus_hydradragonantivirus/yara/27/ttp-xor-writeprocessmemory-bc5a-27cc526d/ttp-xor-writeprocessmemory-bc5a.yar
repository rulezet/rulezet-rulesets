rule TTP_XOR_WriteProcessMemory_bc5a {
  strings:
    $key_bc5a = { eb 28 [2] d9 0a [2] df 3f [2] f1 3f [2] ce 23 }

  condition:
    any of them
}