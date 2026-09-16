rule TTP_XOR_WriteProcessMemory_6558 {
  strings:
    $key_6558 = { 32 2a [2] 00 08 [2] 06 3d [2] 28 3d [2] 17 21 }

  condition:
    any of them
}