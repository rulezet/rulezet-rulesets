rule TTP_XOR_WriteProcessMemory_bc37 {
  strings:
    $key_bc37 = { eb 45 [2] d9 67 [2] df 52 [2] f1 52 [2] ce 4e }

  condition:
    any of them
}