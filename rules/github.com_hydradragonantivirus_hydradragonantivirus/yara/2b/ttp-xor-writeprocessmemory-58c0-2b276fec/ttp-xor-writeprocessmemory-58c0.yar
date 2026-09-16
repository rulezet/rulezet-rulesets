rule TTP_XOR_WriteProcessMemory_58c0 {
  strings:
    $key_58c0 = { 0f b2 [2] 3d 90 [2] 3b a5 [2] 15 a5 [2] 2a b9 }

  condition:
    any of them
}