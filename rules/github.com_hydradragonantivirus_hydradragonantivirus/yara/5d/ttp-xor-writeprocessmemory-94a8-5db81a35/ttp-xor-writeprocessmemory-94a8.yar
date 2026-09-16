rule TTP_XOR_WriteProcessMemory_94a8 {
  strings:
    $key_94a8 = { c3 da [2] f1 f8 [2] f7 cd [2] d9 cd [2] e6 d1 }

  condition:
    any of them
}