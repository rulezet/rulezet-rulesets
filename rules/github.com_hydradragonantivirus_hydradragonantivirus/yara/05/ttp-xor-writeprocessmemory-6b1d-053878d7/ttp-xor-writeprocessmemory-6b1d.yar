rule TTP_XOR_WriteProcessMemory_6b1d {
  strings:
    $key_6b1d = { 3c 6f [2] 0e 4d [2] 08 78 [2] 26 78 [2] 19 64 }

  condition:
    any of them
}