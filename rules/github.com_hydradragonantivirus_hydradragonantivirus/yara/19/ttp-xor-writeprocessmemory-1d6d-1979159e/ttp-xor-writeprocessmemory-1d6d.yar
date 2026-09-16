rule TTP_XOR_WriteProcessMemory_1d6d {
  strings:
    $key_1d6d = { 4a 1f [2] 78 3d [2] 7e 08 [2] 50 08 [2] 6f 14 }

  condition:
    any of them
}