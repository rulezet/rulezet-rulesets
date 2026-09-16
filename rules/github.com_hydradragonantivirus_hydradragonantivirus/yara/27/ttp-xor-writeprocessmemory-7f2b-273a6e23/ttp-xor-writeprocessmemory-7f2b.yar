rule TTP_XOR_WriteProcessMemory_7f2b {
  strings:
    $key_7f2b = { 28 59 [2] 1a 7b [2] 1c 4e [2] 32 4e [2] 0d 52 }

  condition:
    any of them
}