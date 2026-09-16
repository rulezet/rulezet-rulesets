rule TTP_XOR_WriteProcessMemory_7e2b {
  strings:
    $key_7e2b = { 29 59 [2] 1b 7b [2] 1d 4e [2] 33 4e [2] 0c 52 }

  condition:
    any of them
}