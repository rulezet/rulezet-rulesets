rule TTP_XOR_WriteProcessMemory_602d {
  strings:
    $key_602d = { 37 5f [2] 05 7d [2] 03 48 [2] 2d 48 [2] 12 54 }

  condition:
    any of them
}