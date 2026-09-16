rule TTP_XOR_WriteProcessMemory_9438 {
  strings:
    $key_9438 = { c3 4a [2] f1 68 [2] f7 5d [2] d9 5d [2] e6 41 }

  condition:
    any of them
}