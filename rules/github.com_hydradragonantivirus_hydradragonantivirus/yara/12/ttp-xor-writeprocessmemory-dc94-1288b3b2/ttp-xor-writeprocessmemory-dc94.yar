rule TTP_XOR_WriteProcessMemory_dc94 {
  strings:
    $key_dc94 = { 8b e6 [2] b9 c4 [2] bf f1 [2] 91 f1 [2] ae ed }

  condition:
    any of them
}