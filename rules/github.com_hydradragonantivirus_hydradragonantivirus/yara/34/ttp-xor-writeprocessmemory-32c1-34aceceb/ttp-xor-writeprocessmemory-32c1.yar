rule TTP_XOR_WriteProcessMemory_32c1 {
  strings:
    $key_32c1 = { 65 b3 [2] 57 91 [2] 51 a4 [2] 7f a4 [2] 40 b8 }

  condition:
    any of them
}