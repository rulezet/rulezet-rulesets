rule TTP_XOR_WriteProcessMemory_15ce {
  strings:
    $key_15ce = { 42 bc [2] 70 9e [2] 76 ab [2] 58 ab [2] 67 b7 }

  condition:
    any of them
}