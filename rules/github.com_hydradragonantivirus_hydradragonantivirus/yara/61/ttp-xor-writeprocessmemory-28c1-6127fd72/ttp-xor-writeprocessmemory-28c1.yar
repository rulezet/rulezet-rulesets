rule TTP_XOR_WriteProcessMemory_28c1 {
  strings:
    $key_28c1 = { 7f b3 [2] 4d 91 [2] 4b a4 [2] 65 a4 [2] 5a b8 }

  condition:
    any of them
}