rule TTP_XOR_WriteProcessMemory_0dc0 {
  strings:
    $key_0dc0 = { 5a b2 [2] 68 90 [2] 6e a5 [2] 40 a5 [2] 7f b9 }

  condition:
    any of them
}