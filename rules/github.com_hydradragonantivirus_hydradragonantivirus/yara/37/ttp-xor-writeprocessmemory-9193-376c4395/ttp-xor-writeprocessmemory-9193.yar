rule TTP_XOR_WriteProcessMemory_9193 {
  strings:
    $key_9193 = { c6 e1 [2] f4 c3 [2] f2 f6 [2] dc f6 [2] e3 ea }

  condition:
    any of them
}