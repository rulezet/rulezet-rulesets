rule TTP_XOR_WriteProcessMemory_9bb4 {
  strings:
    $key_9bb4 = { cc c6 [2] fe e4 [2] f8 d1 [2] d6 d1 [2] e9 cd }

  condition:
    any of them
}