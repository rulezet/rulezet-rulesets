rule TTP_XOR_WriteProcessMemory_405b {
  strings:
    $key_405b = { 17 29 [2] 25 0b [2] 23 3e [2] 0d 3e [2] 32 22 }

  condition:
    any of them
}