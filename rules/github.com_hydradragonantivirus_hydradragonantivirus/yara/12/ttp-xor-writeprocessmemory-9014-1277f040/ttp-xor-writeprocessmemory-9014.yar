rule TTP_XOR_WriteProcessMemory_9014 {
  strings:
    $key_9014 = { c7 66 [2] f5 44 [2] f3 71 [2] dd 71 [2] e2 6d }

  condition:
    any of them
}