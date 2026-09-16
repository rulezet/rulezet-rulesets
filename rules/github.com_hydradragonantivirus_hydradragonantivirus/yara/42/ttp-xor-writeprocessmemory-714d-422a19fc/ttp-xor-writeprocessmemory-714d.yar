rule TTP_XOR_WriteProcessMemory_714d {
  strings:
    $key_714d = { 26 3f [2] 14 1d [2] 12 28 [2] 3c 28 [2] 03 34 }

  condition:
    any of them
}