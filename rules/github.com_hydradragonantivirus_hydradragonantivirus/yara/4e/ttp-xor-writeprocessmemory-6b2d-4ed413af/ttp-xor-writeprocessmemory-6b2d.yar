rule TTP_XOR_WriteProcessMemory_6b2d {
  strings:
    $key_6b2d = { 3c 5f [2] 0e 7d [2] 08 48 [2] 26 48 [2] 19 54 }

  condition:
    any of them
}