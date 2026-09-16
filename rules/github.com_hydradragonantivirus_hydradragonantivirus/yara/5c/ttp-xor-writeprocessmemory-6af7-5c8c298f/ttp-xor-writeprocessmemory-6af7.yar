rule TTP_XOR_WriteProcessMemory_6af7 {
  strings:
    $key_6af7 = { 3d 85 [2] 0f a7 [2] 09 92 [2] 27 92 [2] 18 8e }

  condition:
    any of them
}