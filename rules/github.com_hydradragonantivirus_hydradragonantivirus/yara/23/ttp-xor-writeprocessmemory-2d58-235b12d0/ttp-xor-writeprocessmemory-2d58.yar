rule TTP_XOR_WriteProcessMemory_2d58 {
  strings:
    $key_2d58 = { 7a 2a [2] 48 08 [2] 4e 3d [2] 60 3d [2] 5f 21 }

  condition:
    any of them
}