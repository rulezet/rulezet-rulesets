rule TTP_XOR_WriteProcessMemory_0b6d {
  strings:
    $key_0b6d = { 5c 1f [2] 6e 3d [2] 68 08 [2] 46 08 [2] 79 14 }

  condition:
    any of them
}