rule TTP_XOR_WriteProcessMemory_22ce {
  strings:
    $key_22ce = { 75 bc [2] 47 9e [2] 41 ab [2] 6f ab [2] 50 b7 }

  condition:
    any of them
}