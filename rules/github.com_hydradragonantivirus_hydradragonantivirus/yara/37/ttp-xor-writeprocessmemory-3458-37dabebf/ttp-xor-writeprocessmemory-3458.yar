rule TTP_XOR_WriteProcessMemory_3458 {
  strings:
    $key_3458 = { 63 2a [2] 51 08 [2] 57 3d [2] 79 3d [2] 46 21 }

  condition:
    any of them
}