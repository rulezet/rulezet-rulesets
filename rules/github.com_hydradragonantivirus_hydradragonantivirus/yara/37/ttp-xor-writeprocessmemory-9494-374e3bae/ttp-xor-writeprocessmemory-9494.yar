rule TTP_XOR_WriteProcessMemory_9494 {
  strings:
    $key_9494 = { c3 e6 [2] f1 c4 [2] f7 f1 [2] d9 f1 [2] e6 ed }

  condition:
    any of them
}