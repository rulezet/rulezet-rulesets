rule TTP_XOR_WriteProcessMemory_838b {
  strings:
    $key_838b = { d4 f9 [2] e6 db [2] e0 ee [2] ce ee [2] f1 f2 }

  condition:
    any of them
}