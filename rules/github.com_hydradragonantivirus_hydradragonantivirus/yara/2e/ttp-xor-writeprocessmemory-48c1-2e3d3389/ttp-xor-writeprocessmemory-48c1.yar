rule TTP_XOR_WriteProcessMemory_48c1 {
  strings:
    $key_48c1 = { 1f b3 [2] 2d 91 [2] 2b a4 [2] 05 a4 [2] 3a b8 }

  condition:
    any of them
}