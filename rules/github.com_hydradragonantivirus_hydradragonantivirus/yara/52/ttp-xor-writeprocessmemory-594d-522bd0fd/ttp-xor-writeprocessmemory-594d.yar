rule TTP_XOR_WriteProcessMemory_594d {
  strings:
    $key_594d = { 0e 3f [2] 3c 1d [2] 3a 28 [2] 14 28 [2] 2b 34 }

  condition:
    any of them
}