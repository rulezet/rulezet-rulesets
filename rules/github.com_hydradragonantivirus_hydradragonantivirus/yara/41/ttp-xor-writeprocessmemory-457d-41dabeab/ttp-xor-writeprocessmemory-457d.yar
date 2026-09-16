rule TTP_XOR_WriteProcessMemory_457d {
  strings:
    $key_457d = { 12 0f [2] 20 2d [2] 26 18 [2] 08 18 [2] 37 04 }

  condition:
    any of them
}