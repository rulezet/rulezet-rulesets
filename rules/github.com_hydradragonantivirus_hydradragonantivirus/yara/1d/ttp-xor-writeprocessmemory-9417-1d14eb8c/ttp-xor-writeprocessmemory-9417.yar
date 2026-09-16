rule TTP_XOR_WriteProcessMemory_9417 {
  strings:
    $key_9417 = { c3 65 [2] f1 47 [2] f7 72 [2] d9 72 [2] e6 6e }

  condition:
    any of them
}