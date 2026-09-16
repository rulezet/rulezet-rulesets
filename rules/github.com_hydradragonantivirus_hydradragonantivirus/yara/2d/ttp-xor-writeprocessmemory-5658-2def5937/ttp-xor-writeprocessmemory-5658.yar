rule TTP_XOR_WriteProcessMemory_5658 {
  strings:
    $key_5658 = { 01 2a [2] 33 08 [2] 35 3d [2] 1b 3d [2] 24 21 }

  condition:
    any of them
}