rule TTP_XOR_WriteProcessMemory_6658 {
  strings:
    $key_6658 = { 31 2a [2] 03 08 [2] 05 3d [2] 2b 3d [2] 14 21 }

  condition:
    any of them
}