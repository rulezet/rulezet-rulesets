rule TTP_XOR_WriteProcessMemory_94e8 {
  strings:
    $key_94e8 = { c3 9a [2] f1 b8 [2] f7 8d [2] d9 8d [2] e6 91 }

  condition:
    any of them
}