rule TTP_XOR_WriteProcessMemory_377c {
  strings:
    $key_377c = { 60 0e [2] 52 2c [2] 54 19 [2] 7a 19 [2] 45 05 }

  condition:
    any of them
}