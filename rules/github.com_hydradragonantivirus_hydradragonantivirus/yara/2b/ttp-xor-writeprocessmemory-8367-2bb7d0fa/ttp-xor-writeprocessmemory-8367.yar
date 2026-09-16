rule TTP_XOR_WriteProcessMemory_8367 {
  strings:
    $key_8367 = { d4 15 [2] e6 37 [2] e0 02 [2] ce 02 [2] f1 1e }

  condition:
    any of them
}