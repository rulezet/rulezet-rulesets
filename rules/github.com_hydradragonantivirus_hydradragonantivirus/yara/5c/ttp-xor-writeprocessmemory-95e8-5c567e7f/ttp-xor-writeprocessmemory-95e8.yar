rule TTP_XOR_WriteProcessMemory_95e8 {
  strings:
    $key_95e8 = { c2 9a [2] f0 b8 [2] f6 8d [2] d8 8d [2] e7 91 }

  condition:
    any of them
}