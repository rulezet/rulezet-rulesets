rule TTP_XOR_WriteProcessMemory_bc32 {
  strings:
    $key_bc32 = { eb 40 [2] d9 62 [2] df 57 [2] f1 57 [2] ce 4b }

  condition:
    any of them
}