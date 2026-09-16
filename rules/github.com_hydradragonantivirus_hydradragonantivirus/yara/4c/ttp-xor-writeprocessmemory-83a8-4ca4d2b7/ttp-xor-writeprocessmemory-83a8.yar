rule TTP_XOR_WriteProcessMemory_83a8 {
  strings:
    $key_83a8 = { d4 da [2] e6 f8 [2] e0 cd [2] ce cd [2] f1 d1 }

  condition:
    any of them
}