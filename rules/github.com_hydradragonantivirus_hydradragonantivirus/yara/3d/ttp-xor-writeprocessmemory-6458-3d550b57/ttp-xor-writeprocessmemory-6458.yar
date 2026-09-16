rule TTP_XOR_WriteProcessMemory_6458 {
  strings:
    $key_6458 = { 33 2a [2] 01 08 [2] 07 3d [2] 29 3d [2] 16 21 }

  condition:
    any of them
}