rule TTP_XOR_WriteProcessMemory_9270 {
  strings:
    $key_9270 = { c5 02 [2] f7 20 [2] f1 15 [2] df 15 [2] e0 09 }

  condition:
    any of them
}