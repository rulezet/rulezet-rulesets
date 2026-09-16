rule TTP_XOR_WriteProcessMemory_01c4 {
  strings:
    $key_01c4 = { 56 b6 [2] 64 94 [2] 62 a1 [2] 4c a1 [2] 73 bd }

  condition:
    any of them
}