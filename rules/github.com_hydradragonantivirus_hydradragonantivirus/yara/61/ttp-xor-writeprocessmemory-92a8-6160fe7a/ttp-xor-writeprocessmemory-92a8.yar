rule TTP_XOR_WriteProcessMemory_92a8 {
  strings:
    $key_92a8 = { c5 da [2] f7 f8 [2] f1 cd [2] df cd [2] e0 d1 }

  condition:
    any of them
}