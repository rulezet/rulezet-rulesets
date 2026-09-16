rule TTP_XOR_WriteProcessMemory_426b {
  strings:
    $key_426b = { 15 19 [2] 27 3b [2] 21 0e [2] 0f 0e [2] 30 12 }

  condition:
    any of them
}