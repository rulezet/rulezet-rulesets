rule TTP_XOR_WriteProcessMemory_922c {
  strings:
    $key_922c = { c5 5e [2] f7 7c [2] f1 49 [2] df 49 [2] e0 55 }

  condition:
    any of them
}