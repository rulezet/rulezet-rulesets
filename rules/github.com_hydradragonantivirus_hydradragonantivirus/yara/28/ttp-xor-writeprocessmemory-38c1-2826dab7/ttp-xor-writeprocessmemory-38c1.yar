rule TTP_XOR_WriteProcessMemory_38c1 {
  strings:
    $key_38c1 = { 6f b3 [2] 5d 91 [2] 5b a4 [2] 75 a4 [2] 4a b8 }

  condition:
    any of them
}