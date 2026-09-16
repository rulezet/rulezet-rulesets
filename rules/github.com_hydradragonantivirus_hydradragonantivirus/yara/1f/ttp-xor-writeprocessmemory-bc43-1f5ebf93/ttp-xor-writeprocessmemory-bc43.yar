rule TTP_XOR_WriteProcessMemory_bc43 {
  strings:
    $key_bc43 = { eb 31 [2] d9 13 [2] df 26 [2] f1 26 [2] ce 3a }

  condition:
    any of them
}