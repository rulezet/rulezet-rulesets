rule TTP_XOR_WriteProcessMemory_4d4d {
  strings:
    $key_4d4d = { 1a 3f [2] 28 1d [2] 2e 28 [2] 00 28 [2] 3f 34 }

  condition:
    any of them
}