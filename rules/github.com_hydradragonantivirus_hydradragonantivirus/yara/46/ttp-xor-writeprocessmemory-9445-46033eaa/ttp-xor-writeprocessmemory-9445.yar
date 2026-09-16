rule TTP_XOR_WriteProcessMemory_9445 {
  strings:
    $key_9445 = { c3 37 [2] f1 15 [2] f7 20 [2] d9 20 [2] e6 3c }

  condition:
    any of them
}