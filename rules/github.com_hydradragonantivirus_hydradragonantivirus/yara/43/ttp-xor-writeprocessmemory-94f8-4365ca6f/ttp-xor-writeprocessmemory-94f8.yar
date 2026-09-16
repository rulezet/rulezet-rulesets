rule TTP_XOR_WriteProcessMemory_94f8 {
  strings:
    $key_94f8 = { c3 8a [2] f1 a8 [2] f7 9d [2] d9 9d [2] e6 81 }

  condition:
    any of them
}