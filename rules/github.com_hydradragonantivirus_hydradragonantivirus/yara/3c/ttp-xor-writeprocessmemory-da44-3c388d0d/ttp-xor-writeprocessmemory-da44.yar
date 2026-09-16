rule TTP_XOR_WriteProcessMemory_da44 {
  strings:
    $key_da44 = { 8d 36 [2] bf 14 [2] b9 21 [2] 97 21 [2] a8 3d }

  condition:
    any of them
}