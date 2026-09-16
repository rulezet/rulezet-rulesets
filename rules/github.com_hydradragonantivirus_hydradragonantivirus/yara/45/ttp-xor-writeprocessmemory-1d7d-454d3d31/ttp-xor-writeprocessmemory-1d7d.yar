rule TTP_XOR_WriteProcessMemory_1d7d {
  strings:
    $key_1d7d = { 4a 0f [2] 78 2d [2] 7e 18 [2] 50 18 [2] 6f 04 }

  condition:
    any of them
}