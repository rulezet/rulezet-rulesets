rule TTP_XOR_WriteProcessMemory_20c1 {
  strings:
    $key_20c1 = { 77 b3 [2] 45 91 [2] 43 a4 [2] 6d a4 [2] 52 b8 }

  condition:
    any of them
}