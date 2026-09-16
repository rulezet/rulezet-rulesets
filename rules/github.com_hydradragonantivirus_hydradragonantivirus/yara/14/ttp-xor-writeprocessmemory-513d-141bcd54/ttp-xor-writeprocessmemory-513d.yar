rule TTP_XOR_WriteProcessMemory_513d {
  strings:
    $key_513d = { 06 4f [2] 34 6d [2] 32 58 [2] 1c 58 [2] 23 44 }

  condition:
    any of them
}