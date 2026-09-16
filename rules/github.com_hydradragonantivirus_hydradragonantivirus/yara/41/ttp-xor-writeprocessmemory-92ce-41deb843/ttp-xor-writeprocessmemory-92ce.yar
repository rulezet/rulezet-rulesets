rule TTP_XOR_WriteProcessMemory_92ce {
  strings:
    $key_92ce = { c5 bc [2] f7 9e [2] f1 ab [2] df ab [2] e0 b7 }

  condition:
    any of them
}