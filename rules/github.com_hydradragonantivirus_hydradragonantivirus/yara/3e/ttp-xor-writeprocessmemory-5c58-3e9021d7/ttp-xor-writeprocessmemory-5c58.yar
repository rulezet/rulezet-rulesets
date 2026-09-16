rule TTP_XOR_WriteProcessMemory_5c58 {
  strings:
    $key_5c58 = { 0b 2a [2] 39 08 [2] 3f 3d [2] 11 3d [2] 2e 21 }

  condition:
    any of them
}