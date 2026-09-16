rule TTP_XOR_WriteProcessMemory_9443 {
  strings:
    $key_9443 = { c3 31 [2] f1 13 [2] f7 26 [2] d9 26 [2] e6 3a }

  condition:
    any of them
}