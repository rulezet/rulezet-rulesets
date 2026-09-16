rule TTP_XOR_WriteProcessMemory_31ce {
  strings:
    $key_31ce = { 66 bc [2] 54 9e [2] 52 ab [2] 7c ab [2] 43 b7 }

  condition:
    any of them
}