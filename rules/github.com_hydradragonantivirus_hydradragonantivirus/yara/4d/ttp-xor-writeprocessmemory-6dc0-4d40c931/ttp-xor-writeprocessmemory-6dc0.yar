rule TTP_XOR_WriteProcessMemory_6dc0 {
  strings:
    $key_6dc0 = { 3a b2 [2] 08 90 [2] 0e a5 [2] 20 a5 [2] 1f b9 }

  condition:
    any of them
}