rule TTP_XOR_WriteProcessMemory_463d {
  strings:
    $key_463d = { 11 4f [2] 23 6d [2] 25 58 [2] 0b 58 [2] 34 44 }

  condition:
    any of them
}