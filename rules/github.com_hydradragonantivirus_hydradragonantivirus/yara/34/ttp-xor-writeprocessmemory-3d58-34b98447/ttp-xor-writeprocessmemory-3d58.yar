rule TTP_XOR_WriteProcessMemory_3d58 {
  strings:
    $key_3d58 = { 6a 2a [2] 58 08 [2] 5e 3d [2] 70 3d [2] 4f 21 }

  condition:
    any of them
}