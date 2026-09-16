rule TTP_XOR_WriteProcessMemory_41c4 {
  strings:
    $key_41c4 = { 16 b6 [2] 24 94 [2] 22 a1 [2] 0c a1 [2] 33 bd }

  condition:
    any of them
}