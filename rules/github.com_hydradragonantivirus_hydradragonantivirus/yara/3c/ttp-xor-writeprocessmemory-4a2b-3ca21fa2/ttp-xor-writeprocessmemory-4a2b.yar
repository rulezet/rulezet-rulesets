rule TTP_XOR_WriteProcessMemory_4a2b {
  strings:
    $key_4a2b = { 1d 59 [2] 2f 7b [2] 29 4e [2] 07 4e [2] 38 52 }

  condition:
    any of them
}