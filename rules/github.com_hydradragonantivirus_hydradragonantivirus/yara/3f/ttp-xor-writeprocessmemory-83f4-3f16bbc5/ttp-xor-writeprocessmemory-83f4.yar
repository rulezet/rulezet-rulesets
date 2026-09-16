rule TTP_XOR_WriteProcessMemory_83f4 {
  strings:
    $key_83f4 = { d4 86 [2] e6 a4 [2] e0 91 [2] ce 91 [2] f1 8d }

  condition:
    any of them
}