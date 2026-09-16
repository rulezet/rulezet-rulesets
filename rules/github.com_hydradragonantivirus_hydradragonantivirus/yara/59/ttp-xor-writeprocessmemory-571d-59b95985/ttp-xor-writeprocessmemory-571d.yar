rule TTP_XOR_WriteProcessMemory_571d {
  strings:
    $key_571d = { 00 6f [2] 32 4d [2] 34 78 [2] 1a 78 [2] 25 64 }

  condition:
    any of them
}