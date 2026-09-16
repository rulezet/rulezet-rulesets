rule TTP_XOR_WriteProcessMemory_94f1 {
  strings:
    $key_94f1 = { c3 83 [2] f1 a1 [2] f7 94 [2] d9 94 [2] e6 88 }

  condition:
    any of them
}