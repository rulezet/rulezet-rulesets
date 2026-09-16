rule TTP_XOR_WriteProcessMemory_5358 {
  strings:
    $key_5358 = { 04 2a [2] 36 08 [2] 30 3d [2] 1e 3d [2] 21 21 }

  condition:
    any of them
}