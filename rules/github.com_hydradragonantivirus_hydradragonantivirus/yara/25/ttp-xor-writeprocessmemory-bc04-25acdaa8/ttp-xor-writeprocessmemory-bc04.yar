rule TTP_XOR_WriteProcessMemory_bc04 {
  strings:
    $key_bc04 = { eb 76 [2] d9 54 [2] df 61 [2] f1 61 [2] ce 7d }

  condition:
    any of them
}