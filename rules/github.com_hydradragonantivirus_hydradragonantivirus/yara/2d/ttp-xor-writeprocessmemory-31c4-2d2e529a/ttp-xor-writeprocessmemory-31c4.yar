rule TTP_XOR_WriteProcessMemory_31c4 {
  strings:
    $key_31c4 = { 66 b6 [2] 54 94 [2] 52 a1 [2] 7c a1 [2] 43 bd }

  condition:
    any of them
}