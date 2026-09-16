rule TTP_XOR_WriteProcessMemory_02c4 {
  strings:
    $key_02c4 = { 55 b6 [2] 67 94 [2] 61 a1 [2] 4f a1 [2] 70 bd }

  condition:
    any of them
}