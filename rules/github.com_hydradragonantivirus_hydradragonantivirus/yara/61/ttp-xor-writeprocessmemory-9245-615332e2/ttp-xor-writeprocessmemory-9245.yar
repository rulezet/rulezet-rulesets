rule TTP_XOR_WriteProcessMemory_9245 {
  strings:
    $key_9245 = { c5 37 [2] f7 15 [2] f1 20 [2] df 20 [2] e0 3c }

  condition:
    any of them
}