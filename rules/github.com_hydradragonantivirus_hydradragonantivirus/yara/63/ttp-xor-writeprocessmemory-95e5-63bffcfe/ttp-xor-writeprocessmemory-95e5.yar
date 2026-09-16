rule TTP_XOR_WriteProcessMemory_95e5 {
  strings:
    $key_95e5 = { c2 97 [2] f0 b5 [2] f6 80 [2] d8 80 [2] e7 9c }

  condition:
    any of them
}