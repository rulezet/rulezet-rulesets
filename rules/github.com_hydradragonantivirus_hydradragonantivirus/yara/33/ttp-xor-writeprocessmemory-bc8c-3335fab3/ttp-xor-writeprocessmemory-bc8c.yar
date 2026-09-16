rule TTP_XOR_WriteProcessMemory_bc8c {
  strings:
    $key_bc8c = { eb fe [2] d9 dc [2] df e9 [2] f1 e9 [2] ce f5 }

  condition:
    any of them
}