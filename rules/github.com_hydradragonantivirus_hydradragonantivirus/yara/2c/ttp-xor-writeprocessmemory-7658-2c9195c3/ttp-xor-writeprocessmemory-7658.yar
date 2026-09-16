rule TTP_XOR_WriteProcessMemory_7658 {
  strings:
    $key_7658 = { 21 2a [2] 13 08 [2] 15 3d [2] 3b 3d [2] 04 21 }

  condition:
    any of them
}