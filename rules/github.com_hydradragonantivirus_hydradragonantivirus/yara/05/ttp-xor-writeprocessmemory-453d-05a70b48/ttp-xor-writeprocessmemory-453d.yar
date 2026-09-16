rule TTP_XOR_WriteProcessMemory_453d {
  strings:
    $key_453d = { 12 4f [2] 20 6d [2] 26 58 [2] 08 58 [2] 37 44 }

  condition:
    any of them
}