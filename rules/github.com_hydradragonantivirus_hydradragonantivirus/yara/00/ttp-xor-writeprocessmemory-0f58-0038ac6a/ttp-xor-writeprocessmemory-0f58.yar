rule TTP_XOR_WriteProcessMemory_0f58 {
  strings:
    $key_0f58 = { 58 2a [2] 6a 08 [2] 6c 3d [2] 42 3d [2] 7d 21 }

  condition:
    any of them
}