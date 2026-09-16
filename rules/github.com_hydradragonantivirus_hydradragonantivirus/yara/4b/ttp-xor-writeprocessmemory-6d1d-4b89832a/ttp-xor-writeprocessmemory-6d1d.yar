rule TTP_XOR_WriteProcessMemory_6d1d {
  strings:
    $key_6d1d = { 3a 6f [2] 08 4d [2] 0e 78 [2] 20 78 [2] 1f 64 }

  condition:
    any of them
}