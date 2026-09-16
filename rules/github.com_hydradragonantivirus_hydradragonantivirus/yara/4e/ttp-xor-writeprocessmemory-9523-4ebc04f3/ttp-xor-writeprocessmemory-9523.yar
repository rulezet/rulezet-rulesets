rule TTP_XOR_WriteProcessMemory_9523 {
  strings:
    $key_9523 = { c2 51 [2] f0 73 [2] f6 46 [2] d8 46 [2] e7 5a }

  condition:
    any of them
}