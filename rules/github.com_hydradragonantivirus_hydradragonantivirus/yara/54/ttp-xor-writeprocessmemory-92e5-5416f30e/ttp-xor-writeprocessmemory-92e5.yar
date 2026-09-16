rule TTP_XOR_WriteProcessMemory_92e5 {
  strings:
    $key_92e5 = { c5 97 [2] f7 b5 [2] f1 80 [2] df 80 [2] e0 9c }

  condition:
    any of them
}