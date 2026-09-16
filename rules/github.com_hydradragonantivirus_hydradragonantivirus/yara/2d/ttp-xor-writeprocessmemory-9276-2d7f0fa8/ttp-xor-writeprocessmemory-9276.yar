rule TTP_XOR_WriteProcessMemory_9276 {
  strings:
    $key_9276 = { c5 04 [2] f7 26 [2] f1 13 [2] df 13 [2] e0 0f }

  condition:
    any of them
}