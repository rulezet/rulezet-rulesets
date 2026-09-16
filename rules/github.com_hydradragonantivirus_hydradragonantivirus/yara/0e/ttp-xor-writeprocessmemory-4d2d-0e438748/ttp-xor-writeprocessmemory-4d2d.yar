rule TTP_XOR_WriteProcessMemory_4d2d {
  strings:
    $key_4d2d = { 1a 5f [2] 28 7d [2] 2e 48 [2] 00 48 [2] 3f 54 }

  condition:
    any of them
}