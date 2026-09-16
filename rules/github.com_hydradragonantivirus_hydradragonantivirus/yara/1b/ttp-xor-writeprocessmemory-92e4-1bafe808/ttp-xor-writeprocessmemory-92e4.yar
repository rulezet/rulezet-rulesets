rule TTP_XOR_WriteProcessMemory_92e4 {
  strings:
    $key_92e4 = { c5 96 [2] f7 b4 [2] f1 81 [2] df 81 [2] e0 9d }

  condition:
    any of them
}