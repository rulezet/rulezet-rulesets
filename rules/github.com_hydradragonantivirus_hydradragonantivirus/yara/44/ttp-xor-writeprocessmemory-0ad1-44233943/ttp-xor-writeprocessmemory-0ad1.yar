rule TTP_XOR_WriteProcessMemory_0ad1 {
  strings:
    $key_0ad1 = { 5d a3 [2] 6f 81 [2] 69 b4 [2] 47 b4 [2] 78 a8 }

  condition:
    any of them
}