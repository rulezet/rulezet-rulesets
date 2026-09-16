rule TTP_XOR_WriteProcessMemory_711d {
  strings:
    $key_711d = { 26 6f [2] 14 4d [2] 12 78 [2] 3c 78 [2] 03 64 }

  condition:
    any of them
}