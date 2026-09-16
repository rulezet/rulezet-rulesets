rule TTP_XOR_WriteProcessMemory_114d {
  strings:
    $key_114d = { 46 3f [2] 74 1d [2] 72 28 [2] 5c 28 [2] 63 34 }

  condition:
    any of them
}