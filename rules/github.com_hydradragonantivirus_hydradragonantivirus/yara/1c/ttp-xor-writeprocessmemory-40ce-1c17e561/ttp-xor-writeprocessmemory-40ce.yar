rule TTP_XOR_WriteProcessMemory_40ce {
  strings:
    $key_40ce = { 17 bc [2] 25 9e [2] 23 ab [2] 0d ab [2] 32 b7 }

  condition:
    any of them
}