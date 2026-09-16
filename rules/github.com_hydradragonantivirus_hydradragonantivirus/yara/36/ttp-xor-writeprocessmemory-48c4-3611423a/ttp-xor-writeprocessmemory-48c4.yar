rule TTP_XOR_WriteProcessMemory_48c4 {
  strings:
    $key_48c4 = { 1f b6 [2] 2d 94 [2] 2b a1 [2] 05 a1 [2] 3a bd }

  condition:
    any of them
}