rule TTP_XOR_WriteProcessMemory_e6ce {
  strings:
    $key_e6ce = { b1 bc [2] 83 9e [2] 85 ab [2] ab ab [2] 94 b7 }

  condition:
    any of them
}