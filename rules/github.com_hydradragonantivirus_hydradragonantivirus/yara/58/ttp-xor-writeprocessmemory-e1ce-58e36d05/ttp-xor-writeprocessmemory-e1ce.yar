rule TTP_XOR_WriteProcessMemory_e1ce {
  strings:
    $key_e1ce = { b6 bc [2] 84 9e [2] 82 ab [2] ac ab [2] 93 b7 }

  condition:
    any of them
}