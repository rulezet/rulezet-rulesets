rule TTP_XOR_WriteProcessMemory_116d {
  strings:
    $key_116d = { 46 1f [2] 74 3d [2] 72 08 [2] 5c 08 [2] 63 14 }

  condition:
    any of them
}