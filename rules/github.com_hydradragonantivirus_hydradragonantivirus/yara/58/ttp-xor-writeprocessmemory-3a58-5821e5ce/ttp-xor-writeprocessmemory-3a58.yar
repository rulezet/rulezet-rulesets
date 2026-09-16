rule TTP_XOR_WriteProcessMemory_3a58 {
  strings:
    $key_3a58 = { 6d 2a [2] 5f 08 [2] 59 3d [2] 77 3d [2] 48 21 }

  condition:
    any of them
}