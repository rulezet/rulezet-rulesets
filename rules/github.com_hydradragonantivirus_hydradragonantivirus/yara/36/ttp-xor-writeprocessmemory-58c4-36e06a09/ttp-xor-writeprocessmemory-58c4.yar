rule TTP_XOR_WriteProcessMemory_58c4 {
  strings:
    $key_58c4 = { 0f b6 [2] 3d 94 [2] 3b a1 [2] 15 a1 [2] 2a bd }

  condition:
    any of them
}