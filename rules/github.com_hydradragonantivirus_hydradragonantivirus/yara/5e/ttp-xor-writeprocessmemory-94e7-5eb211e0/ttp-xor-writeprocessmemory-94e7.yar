rule TTP_XOR_WriteProcessMemory_94e7 {
  strings:
    $key_94e7 = { c3 95 [2] f1 b7 [2] f7 82 [2] d9 82 [2] e6 9e }

  condition:
    any of them
}