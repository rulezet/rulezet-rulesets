rule TTP_XOR_WriteProcessMemory_1b4d {
  strings:
    $key_1b4d = { 4c 3f [2] 7e 1d [2] 78 28 [2] 56 28 [2] 69 34 }

  condition:
    any of them
}