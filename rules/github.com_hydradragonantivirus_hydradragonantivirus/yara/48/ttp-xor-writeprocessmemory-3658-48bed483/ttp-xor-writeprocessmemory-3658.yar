rule TTP_XOR_WriteProcessMemory_3658 {
  strings:
    $key_3658 = { 61 2a [2] 53 08 [2] 55 3d [2] 7b 3d [2] 44 21 }

  condition:
    any of them
}