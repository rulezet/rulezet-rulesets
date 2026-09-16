rule TTP_XOR_WriteProcessMemory_bc24 {
  strings:
    $key_bc24 = { eb 56 [2] d9 74 [2] df 41 [2] f1 41 [2] ce 5d }

  condition:
    any of them
}