rule TTP_XOR_WriteProcessMemory_9ba6 {
  strings:
    $key_9ba6 = { cc d4 [2] fe f6 [2] f8 c3 [2] d6 c3 [2] e9 df }

  condition:
    any of them
}