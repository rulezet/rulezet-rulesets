rule TTP_XOR_WriteProcessMemory_9396 {
  strings:
    $key_9396 = { c4 e4 [2] f6 c6 [2] f0 f3 [2] de f3 [2] e1 ef }

  condition:
    any of them
}