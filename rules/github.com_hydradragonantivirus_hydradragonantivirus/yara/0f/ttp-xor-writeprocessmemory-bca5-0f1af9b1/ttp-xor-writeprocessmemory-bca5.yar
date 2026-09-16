rule TTP_XOR_WriteProcessMemory_bca5 {
  strings:
    $key_bca5 = { eb d7 [2] d9 f5 [2] df c0 [2] f1 c0 [2] ce dc }

  condition:
    any of them
}