rule TTP_XOR_WriteProcessMemory_9407 {
  strings:
    $key_9407 = { c3 75 [2] f1 57 [2] f7 62 [2] d9 62 [2] e6 7e }

  condition:
    any of them
}