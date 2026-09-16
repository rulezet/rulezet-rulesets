rule TTP_XOR_WriteProcessMemory_4a1d {
  strings:
    $key_4a1d = { 1d 6f [2] 2f 4d [2] 29 78 [2] 07 78 [2] 38 64 }

  condition:
    any of them
}