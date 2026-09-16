rule TTP_XOR_WriteProcessMemory_30c1 {
  strings:
    $key_30c1 = { 67 b3 [2] 55 91 [2] 53 a4 [2] 7d a4 [2] 42 b8 }

  condition:
    any of them
}