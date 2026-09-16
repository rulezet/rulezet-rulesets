rule TTP_XOR_WriteProcessMemory_9433 {
  strings:
    $key_9433 = { c3 41 [2] f1 63 [2] f7 56 [2] d9 56 [2] e6 4a }

  condition:
    any of them
}