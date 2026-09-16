rule TTP_XOR_WriteProcessMemory_07ce {
  strings:
    $key_07ce = { 50 bc [2] 62 9e [2] 64 ab [2] 4a ab [2] 75 b7 }

  condition:
    any of them
}