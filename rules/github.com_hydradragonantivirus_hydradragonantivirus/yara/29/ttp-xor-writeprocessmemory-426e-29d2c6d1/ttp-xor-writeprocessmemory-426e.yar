rule TTP_XOR_WriteProcessMemory_426e {
  strings:
    $key_426e = { 15 1c [2] 27 3e [2] 21 0b [2] 0f 0b [2] 30 17 }

  condition:
    any of them
}