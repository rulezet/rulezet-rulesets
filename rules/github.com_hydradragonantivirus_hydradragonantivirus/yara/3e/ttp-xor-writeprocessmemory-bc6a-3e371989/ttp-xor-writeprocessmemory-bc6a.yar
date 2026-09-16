rule TTP_XOR_WriteProcessMemory_bc6a {
  strings:
    $key_bc6a = { eb 18 [2] d9 3a [2] df 0f [2] f1 0f [2] ce 13 }

  condition:
    any of them
}