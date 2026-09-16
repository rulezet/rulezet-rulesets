rule TTP_XOR_WriteProcessMemory_722b {
  strings:
    $key_722b = { 25 59 [2] 17 7b [2] 11 4e [2] 3f 4e [2] 00 52 }

  condition:
    any of them
}