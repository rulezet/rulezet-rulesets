rule TTP_XOR_WriteProcessMemory_5458 {
  strings:
    $key_5458 = { 03 2a [2] 31 08 [2] 37 3d [2] 19 3d [2] 26 21 }

  condition:
    any of them
}