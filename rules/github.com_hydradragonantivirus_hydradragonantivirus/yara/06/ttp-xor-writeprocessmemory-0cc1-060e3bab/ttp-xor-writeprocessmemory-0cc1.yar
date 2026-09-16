rule TTP_XOR_WriteProcessMemory_0cc1 {
  strings:
    $key_0cc1 = { 5b b3 [2] 69 91 [2] 6f a4 [2] 41 a4 [2] 7e b8 }

  condition:
    any of them
}