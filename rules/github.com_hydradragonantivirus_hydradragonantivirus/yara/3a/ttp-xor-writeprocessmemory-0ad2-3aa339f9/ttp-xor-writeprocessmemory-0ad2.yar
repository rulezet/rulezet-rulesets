rule TTP_XOR_WriteProcessMemory_0ad2 {
  strings:
    $key_0ad2 = { 5d a0 [2] 6f 82 [2] 69 b7 [2] 47 b7 [2] 78 ab }

  condition:
    any of them
}