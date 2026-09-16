rule TTP_XOR_WriteProcessMemory_6b6d {
  strings:
    $key_6b6d = { 3c 1f [2] 0e 3d [2] 08 08 [2] 26 08 [2] 19 14 }

  condition:
    any of them
}