rule TTP_XOR_WriteProcessMemory_046b {
  strings:
    $key_046b = { 53 19 [2] 61 3b [2] 67 0e [2] 49 0e [2] 76 12 }

  condition:
    any of them
}