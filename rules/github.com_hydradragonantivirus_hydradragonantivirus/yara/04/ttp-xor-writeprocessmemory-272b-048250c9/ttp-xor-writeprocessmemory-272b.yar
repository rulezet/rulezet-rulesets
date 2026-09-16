rule TTP_XOR_WriteProcessMemory_272b {
  strings:
    $key_272b = { 70 59 [2] 42 7b [2] 44 4e [2] 6a 4e [2] 55 52 }

  condition:
    any of them
}