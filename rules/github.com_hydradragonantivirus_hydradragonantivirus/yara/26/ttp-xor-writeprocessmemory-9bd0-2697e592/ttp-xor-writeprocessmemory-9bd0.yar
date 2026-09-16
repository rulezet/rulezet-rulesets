rule TTP_XOR_WriteProcessMemory_9bd0 {
  strings:
    $key_9bd0 = { cc a2 [2] fe 80 [2] f8 b5 [2] d6 b5 [2] e9 a9 }

  condition:
    any of them
}