rule TTP_XOR_WriteProcessMemory_2458 {
  strings:
    $key_2458 = { 73 2a [2] 41 08 [2] 47 3d [2] 69 3d [2] 56 21 }

  condition:
    any of them
}