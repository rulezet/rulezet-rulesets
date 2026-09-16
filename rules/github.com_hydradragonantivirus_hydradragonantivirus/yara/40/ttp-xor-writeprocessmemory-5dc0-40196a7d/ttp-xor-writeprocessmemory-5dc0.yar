rule TTP_XOR_WriteProcessMemory_5dc0 {
  strings:
    $key_5dc0 = { 0a b2 [2] 38 90 [2] 3e a5 [2] 10 a5 [2] 2f b9 }

  condition:
    any of them
}