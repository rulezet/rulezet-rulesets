rule TTP_XOR_WriteProcessMemory_6f2b {
  strings:
    $key_6f2b = { 38 59 [2] 0a 7b [2] 0c 4e [2] 22 4e [2] 1d 52 }

  condition:
    any of them
}