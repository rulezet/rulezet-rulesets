rule TTP_XOR_WriteProcessMemory_3d36 {
  strings:
    $key_3d36 = { 6a 44 [2] 58 66 [2] 5e 53 [2] 70 53 [2] 4f 4f }

  condition:
    any of them
}