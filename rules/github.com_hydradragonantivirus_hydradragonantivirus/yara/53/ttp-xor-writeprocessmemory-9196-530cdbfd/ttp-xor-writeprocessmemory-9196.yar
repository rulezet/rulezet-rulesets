rule TTP_XOR_WriteProcessMemory_9196 {
  strings:
    $key_9196 = { c6 e4 [2] f4 c6 [2] f2 f3 [2] dc f3 [2] e3 ef }

  condition:
    any of them
}