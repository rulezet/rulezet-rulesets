rule TTP_XOR_WriteProcessMemory_7e2d {
  strings:
    $key_7e2d = { 29 5f [2] 1b 7d [2] 1d 48 [2] 33 48 [2] 0c 54 }

  condition:
    any of them
}