rule TTP_XOR_WriteProcessMemory_83e8 {
  strings:
    $key_83e8 = { d4 9a [2] e6 b8 [2] e0 8d [2] ce 8d [2] f1 91 }

  condition:
    any of them
}