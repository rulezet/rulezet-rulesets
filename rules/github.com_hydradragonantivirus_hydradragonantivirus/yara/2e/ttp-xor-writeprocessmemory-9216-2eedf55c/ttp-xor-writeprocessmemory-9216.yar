rule TTP_XOR_WriteProcessMemory_9216 {
  strings:
    $key_9216 = { c5 64 [2] f7 46 [2] f1 73 [2] df 73 [2] e0 6f }

  condition:
    any of them
}