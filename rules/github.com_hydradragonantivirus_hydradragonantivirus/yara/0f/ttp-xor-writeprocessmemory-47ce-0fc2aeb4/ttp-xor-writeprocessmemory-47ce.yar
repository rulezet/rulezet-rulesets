rule TTP_XOR_WriteProcessMemory_47ce {
  strings:
    $key_47ce = { 10 bc [2] 22 9e [2] 24 ab [2] 0a ab [2] 35 b7 }

  condition:
    any of them
}