rule TTP_XOR_WriteProcessMemory_923b {
  strings:
    $key_923b = { c5 49 [2] f7 6b [2] f1 5e [2] df 5e [2] e0 42 }

  condition:
    any of them
}