rule TTP_XOR_WriteProcessMemory_57ee {
  strings:
    $key_57ee = { 00 9c [2] 32 be [2] 34 8b [2] 1a 8b [2] 25 97 }

  condition:
    any of them
}