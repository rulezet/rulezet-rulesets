rule TTP_XOR_WriteProcessMemory_656d {
  strings:
    $key_656d = { 32 1f [2] 00 3d [2] 06 08 [2] 28 08 [2] 17 14 }

  condition:
    any of them
}