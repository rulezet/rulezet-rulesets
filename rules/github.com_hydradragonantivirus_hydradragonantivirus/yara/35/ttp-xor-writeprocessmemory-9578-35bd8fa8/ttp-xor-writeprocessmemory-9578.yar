rule TTP_XOR_WriteProcessMemory_9578 {
  strings:
    $key_9578 = { c2 0a [2] f0 28 [2] f6 1d [2] d8 1d [2] e7 01 }

  condition:
    any of them
}