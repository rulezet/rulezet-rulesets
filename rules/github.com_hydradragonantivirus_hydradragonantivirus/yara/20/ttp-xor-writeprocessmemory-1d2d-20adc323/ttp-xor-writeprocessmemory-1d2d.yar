rule TTP_XOR_WriteProcessMemory_1d2d {
  strings:
    $key_1d2d = { 4a 5f [2] 78 7d [2] 7e 48 [2] 50 48 [2] 6f 54 }

  condition:
    any of them
}