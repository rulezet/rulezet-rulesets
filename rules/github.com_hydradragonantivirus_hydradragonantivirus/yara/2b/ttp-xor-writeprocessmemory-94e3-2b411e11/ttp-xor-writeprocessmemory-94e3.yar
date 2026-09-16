rule TTP_XOR_WriteProcessMemory_94e3 {
  strings:
    $key_94e3 = { c3 91 [2] f1 b3 [2] f7 86 [2] d9 86 [2] e6 9a }

  condition:
    any of them
}