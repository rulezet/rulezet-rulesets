rule TTP_XOR_WriteProcessMemory_63ce {
  strings:
    $key_63ce = { 34 bc [2] 06 9e [2] 00 ab [2] 2e ab [2] 11 b7 }

  condition:
    any of them
}