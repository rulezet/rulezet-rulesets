rule TTP_XOR_WriteProcessMemory_33ce {
  strings:
    $key_33ce = { 64 bc [2] 56 9e [2] 50 ab [2] 7e ab [2] 41 b7 }

  condition:
    any of them
}