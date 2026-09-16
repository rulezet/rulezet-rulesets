rule TTP_XOR_WriteProcessMemory_9593 {
  strings:
    $key_9593 = { c2 e1 [2] f0 c3 [2] f6 f6 [2] d8 f6 [2] e7 ea }

  condition:
    any of them
}