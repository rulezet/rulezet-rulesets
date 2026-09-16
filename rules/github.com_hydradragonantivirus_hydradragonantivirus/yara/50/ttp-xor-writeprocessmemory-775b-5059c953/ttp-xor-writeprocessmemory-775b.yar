rule TTP_XOR_WriteProcessMemory_775b {
  strings:
    $key_775b = { 20 29 [2] 12 0b [2] 14 3e [2] 3a 3e [2] 05 22 }

  condition:
    any of them
}