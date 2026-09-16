rule TTP_XOR_WriteProcessMemory_9466 {
  strings:
    $key_9466 = { c3 14 [2] f1 36 [2] f7 03 [2] d9 03 [2] e6 1f }

  condition:
    any of them
}