rule TTP_XOR_WriteProcessMemory_4e2d {
  strings:
    $key_4e2d = { 19 5f [2] 2b 7d [2] 2d 48 [2] 03 48 [2] 3c 54 }

  condition:
    any of them
}