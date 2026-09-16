rule TTP_XOR_WriteProcessMemory_5a58 {
  strings:
    $key_5a58 = { 0d 2a [2] 3f 08 [2] 39 3d [2] 17 3d [2] 28 21 }

  condition:
    any of them
}