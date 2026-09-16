rule TTP_XOR_WriteProcessMemory_6d2d {
  strings:
    $key_6d2d = { 3a 5f [2] 08 7d [2] 0e 48 [2] 20 48 [2] 1f 54 }

  condition:
    any of them
}