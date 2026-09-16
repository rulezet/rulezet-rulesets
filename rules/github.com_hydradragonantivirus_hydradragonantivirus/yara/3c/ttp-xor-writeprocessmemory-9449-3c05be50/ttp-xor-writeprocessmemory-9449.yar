rule TTP_XOR_WriteProcessMemory_9449 {
  strings:
    $key_9449 = { c3 3b [2] f1 19 [2] f7 2c [2] d9 2c [2] e6 30 }

  condition:
    any of them
}