rule TTP_XOR_WriteProcessMemory_2e4d {
  strings:
    $key_2e4d = { 79 3f [2] 4b 1d [2] 4d 28 [2] 63 28 [2] 5c 34 }

  condition:
    any of them
}