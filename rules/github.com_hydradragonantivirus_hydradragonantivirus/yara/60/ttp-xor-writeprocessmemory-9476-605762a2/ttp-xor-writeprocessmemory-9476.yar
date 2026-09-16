rule TTP_XOR_WriteProcessMemory_9476 {
  strings:
    $key_9476 = { c3 04 [2] f1 26 [2] f7 13 [2] d9 13 [2] e6 0f }

  condition:
    any of them
}