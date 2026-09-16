rule TTP_XOR_WriteProcessMemory_9223 {
  strings:
    $key_9223 = { c5 51 [2] f7 73 [2] f1 46 [2] df 46 [2] e0 5a }

  condition:
    any of them
}