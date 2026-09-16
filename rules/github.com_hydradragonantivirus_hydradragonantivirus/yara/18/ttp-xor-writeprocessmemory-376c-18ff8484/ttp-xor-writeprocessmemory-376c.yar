rule TTP_XOR_WriteProcessMemory_376c {
  strings:
    $key_376c = { 60 1e [2] 52 3c [2] 54 09 [2] 7a 09 [2] 45 15 }

  condition:
    any of them
}