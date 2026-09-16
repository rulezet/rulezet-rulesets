rule TTP_XOR_WriteProcessMemory_57e3 {
  strings:
    $key_57e3 = { 00 91 [2] 32 b3 [2] 34 86 [2] 1a 86 [2] 25 9a }

  condition:
    any of them
}