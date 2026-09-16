rule TTP_XOR_WriteProcessMemory_5b1d {
  strings:
    $key_5b1d = { 0c 6f [2] 3e 4d [2] 38 78 [2] 16 78 [2] 29 64 }

  condition:
    any of them
}