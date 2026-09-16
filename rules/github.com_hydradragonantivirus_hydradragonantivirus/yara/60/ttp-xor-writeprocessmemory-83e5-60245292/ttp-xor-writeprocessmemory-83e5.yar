rule TTP_XOR_WriteProcessMemory_83e5 {
  strings:
    $key_83e5 = { d4 97 [2] e6 b5 [2] e0 80 [2] ce 80 [2] f1 9c }

  condition:
    any of them
}