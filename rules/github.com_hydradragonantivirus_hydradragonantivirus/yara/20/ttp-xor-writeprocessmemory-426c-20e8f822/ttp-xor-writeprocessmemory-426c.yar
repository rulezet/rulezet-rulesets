rule TTP_XOR_WriteProcessMemory_426c {
  strings:
    $key_426c = { 15 1e [2] 27 3c [2] 21 09 [2] 0f 09 [2] 30 15 }

  condition:
    any of them
}