rule TTP_XOR_WriteProcessMemory_4d5d {
  strings:
    $key_4d5d = { 1a 2f [2] 28 0d [2] 2e 38 [2] 00 38 [2] 3f 24 }

  condition:
    any of them
}