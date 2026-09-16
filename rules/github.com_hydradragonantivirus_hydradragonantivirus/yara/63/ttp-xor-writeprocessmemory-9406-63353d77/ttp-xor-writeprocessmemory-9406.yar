rule TTP_XOR_WriteProcessMemory_9406 {
  strings:
    $key_9406 = { c3 74 [2] f1 56 [2] f7 63 [2] d9 63 [2] e6 7f }

  condition:
    any of them
}