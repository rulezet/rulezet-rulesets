rule TTP_XOR_WriteProcessMemory_2dc0 {
  strings:
    $key_2dc0 = { 7a b2 [2] 48 90 [2] 4e a5 [2] 60 a5 [2] 5f b9 }

  condition:
    any of them
}