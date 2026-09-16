rule TTP_XOR_WriteProcessMemory_3dc0 {
  strings:
    $key_3dc0 = { 6a b2 [2] 58 90 [2] 5e a5 [2] 70 a5 [2] 4f b9 }

  condition:
    any of them
}