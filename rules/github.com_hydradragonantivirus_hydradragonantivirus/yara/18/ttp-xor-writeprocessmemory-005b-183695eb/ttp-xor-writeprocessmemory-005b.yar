rule TTP_XOR_WriteProcessMemory_005b {
  strings:
    $key_005b = { 57 29 [2] 65 0b [2] 63 3e [2] 4d 3e [2] 72 22 }

  condition:
    any of them
}