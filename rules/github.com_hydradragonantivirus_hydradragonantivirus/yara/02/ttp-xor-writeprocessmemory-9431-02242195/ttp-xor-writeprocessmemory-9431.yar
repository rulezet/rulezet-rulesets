rule TTP_XOR_WriteProcessMemory_9431 {
  strings:
    $key_9431 = { c3 43 [2] f1 61 [2] f7 54 [2] d9 54 [2] e6 48 }

  condition:
    any of them
}