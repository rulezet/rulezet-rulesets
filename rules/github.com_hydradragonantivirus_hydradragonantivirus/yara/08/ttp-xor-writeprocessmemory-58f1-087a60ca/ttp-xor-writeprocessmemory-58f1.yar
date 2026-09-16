rule TTP_XOR_WriteProcessMemory_58f1 {
  strings:
    $key_58f1 = { 0f 83 [2] 3d a1 [2] 3b 94 [2] 15 94 [2] 2a 88 }

  condition:
    any of them
}