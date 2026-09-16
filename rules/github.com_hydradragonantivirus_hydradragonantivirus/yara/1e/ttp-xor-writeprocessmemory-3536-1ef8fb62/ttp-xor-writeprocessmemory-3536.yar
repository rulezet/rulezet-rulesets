rule TTP_XOR_WriteProcessMemory_3536 {
  strings:
    $key_3536 = { 62 44 [2] 50 66 [2] 56 53 [2] 78 53 [2] 47 4f }

  condition:
    any of them
}