rule TTP_XOR_WriteProcessMemory_402d {
  strings:
    $key_402d = { 17 5f [2] 25 7d [2] 23 48 [2] 0d 48 [2] 32 54 }

  condition:
    any of them
}