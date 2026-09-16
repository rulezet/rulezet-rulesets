rule TTP_XOR_WriteProcessMemory_e8ce {
  strings:
    $key_e8ce = { bf bc [2] 8d 9e [2] 8b ab [2] a5 ab [2] 9a b7 }

  condition:
    any of them
}