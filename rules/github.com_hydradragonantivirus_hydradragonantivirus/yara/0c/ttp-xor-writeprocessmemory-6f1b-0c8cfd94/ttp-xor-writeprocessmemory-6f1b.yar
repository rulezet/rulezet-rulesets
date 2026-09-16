rule TTP_XOR_WriteProcessMemory_6f1b {
  strings:
    $key_6f1b = { 38 69 [2] 0a 4b [2] 0c 7e [2] 22 7e [2] 1d 62 }

  condition:
    any of them
}