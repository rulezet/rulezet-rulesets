rule TTP_XOR_WriteProcessMemory_94f3 {
  strings:
    $key_94f3 = { c3 81 [2] f1 a3 [2] f7 96 [2] d9 96 [2] e6 8a }

  condition:
    any of them
}