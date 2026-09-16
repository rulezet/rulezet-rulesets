rule TTP_XOR_WriteProcessMemory_5f2d {
  strings:
    $key_5f2d = { 08 5f [2] 3a 7d [2] 3c 48 [2] 12 48 [2] 2d 54 }

  condition:
    any of them
}