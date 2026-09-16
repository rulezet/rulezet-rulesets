rule TTP_XOR_WriteProcessMemory_9461 {
  strings:
    $key_9461 = { c3 13 [2] f1 31 [2] f7 04 [2] d9 04 [2] e6 18 }

  condition:
    any of them
}