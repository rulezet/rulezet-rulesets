rule TTP_XOR_WriteProcessMemory_bca3 {
  strings:
    $key_bca3 = { eb d1 [2] d9 f3 [2] df c6 [2] f1 c6 [2] ce da }

  condition:
    any of them
}