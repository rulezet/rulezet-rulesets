rule TTP_XOR_WriteProcessMemory_9bd3 {
  strings:
    $key_9bd3 = { cc a1 [2] fe 83 [2] f8 b6 [2] d6 b6 [2] e9 aa }

  condition:
    any of them
}