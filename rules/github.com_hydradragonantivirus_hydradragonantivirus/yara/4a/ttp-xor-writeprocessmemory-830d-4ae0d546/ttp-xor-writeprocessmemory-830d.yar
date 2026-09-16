rule TTP_XOR_WriteProcessMemory_830d {
  strings:
    $key_830d = { d4 7f [2] e6 5d [2] e0 68 [2] ce 68 [2] f1 74 }

  condition:
    any of them
}