rule TTP_XOR_WriteProcessMemory_0b1d {
  strings:
    $key_0b1d = { 5c 6f [2] 6e 4d [2] 68 78 [2] 46 78 [2] 79 64 }

  condition:
    any of them
}