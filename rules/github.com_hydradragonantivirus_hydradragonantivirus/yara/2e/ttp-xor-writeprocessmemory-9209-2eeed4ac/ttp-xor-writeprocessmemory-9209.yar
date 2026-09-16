rule TTP_XOR_WriteProcessMemory_9209 {
  strings:
    $key_9209 = { c5 7b [2] f7 59 [2] f1 6c [2] df 6c [2] e0 70 }

  condition:
    any of them
}