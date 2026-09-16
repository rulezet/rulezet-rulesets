rule TTP_XOR_WriteProcessMemory_4d58 {
  strings:
    $key_4d58 = { 1a 2a [2] 28 08 [2] 2e 3d [2] 00 3d [2] 3f 21 }

  condition:
    any of them
}