rule TTP_XOR_WriteProcessMemory_6b58 {
  strings:
    $key_6b58 = { 3c 2a [2] 0e 08 [2] 08 3d [2] 26 3d [2] 19 21 }

  condition:
    any of them
}