rule TTP_XOR_WriteProcessMemory_0ad0 {
  strings:
    $key_0ad0 = { 5d a2 [2] 6f 80 [2] 69 b5 [2] 47 b5 [2] 78 a9 }

  condition:
    any of them
}