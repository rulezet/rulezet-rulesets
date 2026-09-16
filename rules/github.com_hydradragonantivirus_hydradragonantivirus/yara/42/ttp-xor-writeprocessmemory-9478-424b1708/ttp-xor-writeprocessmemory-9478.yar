rule TTP_XOR_WriteProcessMemory_9478 {
  strings:
    $key_9478 = { c3 0a [2] f1 28 [2] f7 1d [2] d9 1d [2] e6 01 }

  condition:
    any of them
}