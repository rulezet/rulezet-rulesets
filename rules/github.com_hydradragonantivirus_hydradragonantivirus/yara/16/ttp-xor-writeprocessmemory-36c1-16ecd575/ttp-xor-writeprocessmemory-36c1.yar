rule TTP_XOR_WriteProcessMemory_36c1 {
  strings:
    $key_36c1 = { 61 b3 [2] 53 91 [2] 55 a4 [2] 7b a4 [2] 44 b8 }

  condition:
    any of them
}