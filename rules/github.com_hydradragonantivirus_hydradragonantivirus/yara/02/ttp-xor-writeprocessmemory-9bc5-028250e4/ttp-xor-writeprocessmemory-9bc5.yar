rule TTP_XOR_WriteProcessMemory_9bc5 {
  strings:
    $key_9bc5 = { cc b7 [2] fe 95 [2] f8 a0 [2] d6 a0 [2] e9 bc }

  condition:
    any of them
}