rule TTP_XOR_WriteProcessMemory_1fc4 {
  strings:
    $key_1fc4 = { 48 b6 [2] 7a 94 [2] 7c a1 [2] 52 a1 [2] 6d bd }

  condition:
    any of them
}