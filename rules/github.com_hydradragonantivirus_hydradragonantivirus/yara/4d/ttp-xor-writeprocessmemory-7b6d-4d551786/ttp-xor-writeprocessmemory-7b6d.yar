rule TTP_XOR_WriteProcessMemory_7b6d {
  strings:
    $key_7b6d = { 2c 1f [2] 1e 3d [2] 18 08 [2] 36 08 [2] 09 14 }

  condition:
    any of them
}