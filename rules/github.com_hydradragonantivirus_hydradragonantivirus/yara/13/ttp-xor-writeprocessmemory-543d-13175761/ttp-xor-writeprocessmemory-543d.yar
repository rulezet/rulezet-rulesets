rule TTP_XOR_WriteProcessMemory_543d {
  strings:
    $key_543d = { 03 4f [2] 31 6d [2] 37 58 [2] 19 58 [2] 26 44 }

  condition:
    any of them
}