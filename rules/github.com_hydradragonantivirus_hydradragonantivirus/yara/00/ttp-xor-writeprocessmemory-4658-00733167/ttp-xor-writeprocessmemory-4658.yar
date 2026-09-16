rule TTP_XOR_WriteProcessMemory_4658 {
  strings:
    $key_4658 = { 11 2a [2] 23 08 [2] 25 3d [2] 0b 3d [2] 34 21 }

  condition:
    any of them
}