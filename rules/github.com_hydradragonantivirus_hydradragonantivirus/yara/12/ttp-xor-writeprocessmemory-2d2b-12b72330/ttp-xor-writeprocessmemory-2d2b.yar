rule TTP_XOR_WriteProcessMemory_2d2b {
  strings:
    $key_2d2b = { 7a 59 [2] 48 7b [2] 4e 4e [2] 60 4e [2] 5f 52 }

  condition:
    any of them
}