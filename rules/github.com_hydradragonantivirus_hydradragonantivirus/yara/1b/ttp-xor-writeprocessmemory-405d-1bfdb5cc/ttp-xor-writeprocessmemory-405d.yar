rule TTP_XOR_WriteProcessMemory_405d {
  strings:
    $key_405d = { 17 2f [2] 25 0d [2] 23 38 [2] 0d 38 [2] 32 24 }

  condition:
    any of them
}