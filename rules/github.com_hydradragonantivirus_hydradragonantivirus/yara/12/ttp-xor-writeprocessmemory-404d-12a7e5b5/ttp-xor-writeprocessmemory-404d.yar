rule TTP_XOR_WriteProcessMemory_404d {
  strings:
    $key_404d = { 17 3f [2] 25 1d [2] 23 28 [2] 0d 28 [2] 32 34 }

  condition:
    any of them
}