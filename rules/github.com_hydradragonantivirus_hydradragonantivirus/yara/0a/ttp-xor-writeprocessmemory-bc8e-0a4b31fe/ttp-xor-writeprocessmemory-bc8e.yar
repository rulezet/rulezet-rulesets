rule TTP_XOR_WriteProcessMemory_bc8e {
  strings:
    $key_bc8e = { eb fc [2] d9 de [2] df eb [2] f1 eb [2] ce f7 }

  condition:
    any of them
}