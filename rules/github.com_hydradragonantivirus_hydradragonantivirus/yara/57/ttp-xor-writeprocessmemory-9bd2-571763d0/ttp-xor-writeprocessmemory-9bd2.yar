rule TTP_XOR_WriteProcessMemory_9bd2 {
  strings:
    $key_9bd2 = { cc a0 [2] fe 82 [2] f8 b7 [2] d6 b7 [2] e9 ab }

  condition:
    any of them
}