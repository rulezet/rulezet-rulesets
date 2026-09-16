rule TTP_XOR_WriteProcessMemory_e7ce {
  strings:
    $key_e7ce = { b0 bc [2] 82 9e [2] 84 ab [2] aa ab [2] 95 b7 }

  condition:
    any of them
}