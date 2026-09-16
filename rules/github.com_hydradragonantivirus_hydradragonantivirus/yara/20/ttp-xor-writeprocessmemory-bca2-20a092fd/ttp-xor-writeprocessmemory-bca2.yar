rule TTP_XOR_WriteProcessMemory_bca2 {
  strings:
    $key_bca2 = { eb d0 [2] d9 f2 [2] df c7 [2] f1 c7 [2] ce db }

  condition:
    any of them
}