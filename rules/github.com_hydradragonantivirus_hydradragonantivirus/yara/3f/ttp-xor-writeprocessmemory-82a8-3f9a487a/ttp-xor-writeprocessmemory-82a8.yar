rule TTP_XOR_WriteProcessMemory_82a8 {
  strings:
    $key_82a8 = { d5 da [2] e7 f8 [2] e1 cd [2] cf cd [2] f0 d1 }

  condition:
    any of them
}