rule TTP_XOR_WriteProcessMemory_653d {
  strings:
    $key_653d = { 32 4f [2] 00 6d [2] 06 58 [2] 28 58 [2] 17 44 }

  condition:
    any of them
}