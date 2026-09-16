rule TTP_XOR_WriteProcessMemory_9394 {
  strings:
    $key_9394 = { c4 e6 [2] f6 c4 [2] f0 f1 [2] de f1 [2] e1 ed }

  condition:
    any of them
}