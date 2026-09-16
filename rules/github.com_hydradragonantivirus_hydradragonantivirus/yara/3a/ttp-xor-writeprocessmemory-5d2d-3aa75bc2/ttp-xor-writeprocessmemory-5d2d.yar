rule TTP_XOR_WriteProcessMemory_5d2d {
  strings:
    $key_5d2d = { 0a 5f [2] 38 7d [2] 3e 48 [2] 10 48 [2] 2f 54 }

  condition:
    any of them
}