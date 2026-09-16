rule TTP_XOR_WriteProcessMemory_7f2d {
  strings:
    $key_7f2d = { 28 5f [2] 1a 7d [2] 1c 48 [2] 32 48 [2] 0d 54 }

  condition:
    any of them
}