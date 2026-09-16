rule TTP_XOR_WriteProcessMemory_5558 {
  strings:
    $key_5558 = { 02 2a [2] 30 08 [2] 36 3d [2] 18 3d [2] 27 21 }

  condition:
    any of them
}