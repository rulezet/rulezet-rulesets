rule TTP_XOR_WriteProcessMemory_1b1d {
  strings:
    $key_1b1d = { 4c 6f [2] 7e 4d [2] 78 78 [2] 56 78 [2] 69 64 }

  condition:
    any of them
}