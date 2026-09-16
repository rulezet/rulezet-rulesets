rule TTP_XOR_WriteProcessMemory_6af0 {
  strings:
    $key_6af0 = { 3d 82 [2] 0f a0 [2] 09 95 [2] 27 95 [2] 18 89 }

  condition:
    any of them
}