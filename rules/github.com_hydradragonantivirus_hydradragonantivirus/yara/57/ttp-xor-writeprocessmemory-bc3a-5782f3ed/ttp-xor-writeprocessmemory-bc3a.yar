rule TTP_XOR_WriteProcessMemory_bc3a {
  strings:
    $key_bc3a = { eb 48 [2] d9 6a [2] df 5f [2] f1 5f [2] ce 43 }

  condition:
    any of them
}