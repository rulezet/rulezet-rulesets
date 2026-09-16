rule TTP_XOR_WriteProcessMemory_57ea {
  strings:
    $key_57ea = { 00 98 [2] 32 ba [2] 34 8f [2] 1a 8f [2] 25 93 }

  condition:
    any of them
}