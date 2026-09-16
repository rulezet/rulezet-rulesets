rule TTP_XOR_WriteProcessMemory_6af5 {
  strings:
    $key_6af5 = { 3d 87 [2] 0f a5 [2] 09 90 [2] 27 90 [2] 18 8c }

  condition:
    any of them
}