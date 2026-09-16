rule TTP_XOR_WriteProcessMemory_2558 {
  strings:
    $key_2558 = { 72 2a [2] 40 08 [2] 46 3d [2] 68 3d [2] 57 21 }

  condition:
    any of them
}