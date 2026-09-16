rule TTP_XOR_WriteProcessMemory_94e9 {
  strings:
    $key_94e9 = { c3 9b [2] f1 b9 [2] f7 8c [2] d9 8c [2] e6 90 }

  condition:
    any of them
}