rule TTP_XOR_WriteProcessMemory_0f3d {
  strings:
    $key_0f3d = { 58 4f [2] 6a 6d [2] 6c 58 [2] 42 58 [2] 7d 44 }

  condition:
    any of them
}