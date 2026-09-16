rule TTP_XOR_WriteProcessMemory_58f5 {
  strings:
    $key_58f5 = { 0f 87 [2] 3d a5 [2] 3b 90 [2] 15 90 [2] 2a 8c }

  condition:
    any of them
}