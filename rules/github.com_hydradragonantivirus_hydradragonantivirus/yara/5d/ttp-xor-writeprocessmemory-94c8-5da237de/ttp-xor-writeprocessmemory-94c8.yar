rule TTP_XOR_WriteProcessMemory_94c8 {
  strings:
    $key_94c8 = { c3 ba [2] f1 98 [2] f7 ad [2] d9 ad [2] e6 b1 }

  condition:
    any of them
}