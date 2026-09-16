rule TTP_XOR_WriteProcessMemory_78ce {
  strings:
    $key_78ce = { 2f bc [2] 1d 9e [2] 1b ab [2] 35 ab [2] 0a b7 }

  condition:
    any of them
}