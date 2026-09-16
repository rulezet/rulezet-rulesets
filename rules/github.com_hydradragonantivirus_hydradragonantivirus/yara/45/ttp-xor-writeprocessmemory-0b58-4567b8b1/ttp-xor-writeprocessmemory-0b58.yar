rule TTP_XOR_WriteProcessMemory_0b58 {
  strings:
    $key_0b58 = { 5c 2a [2] 6e 08 [2] 68 3d [2] 46 3d [2] 79 21 }

  condition:
    any of them
}