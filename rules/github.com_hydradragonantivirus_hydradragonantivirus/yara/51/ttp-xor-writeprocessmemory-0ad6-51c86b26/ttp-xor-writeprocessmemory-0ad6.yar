rule TTP_XOR_WriteProcessMemory_0ad6 {
  strings:
    $key_0ad6 = { 5d a4 [2] 6f 86 [2] 69 b3 [2] 47 b3 [2] 78 af }

  condition:
    any of them
}