rule TTP_XOR_WriteProcessMemory_bc33 {
  strings:
    $key_bc33 = { eb 41 [2] d9 63 [2] df 56 [2] f1 56 [2] ce 4a }

  condition:
    any of them
}