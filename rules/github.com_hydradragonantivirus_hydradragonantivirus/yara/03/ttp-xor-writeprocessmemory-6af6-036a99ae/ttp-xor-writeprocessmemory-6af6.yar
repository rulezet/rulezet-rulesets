rule TTP_XOR_WriteProcessMemory_6af6 {
  strings:
    $key_6af6 = { 3d 84 [2] 0f a6 [2] 09 93 [2] 27 93 [2] 18 8f }

  condition:
    any of them
}