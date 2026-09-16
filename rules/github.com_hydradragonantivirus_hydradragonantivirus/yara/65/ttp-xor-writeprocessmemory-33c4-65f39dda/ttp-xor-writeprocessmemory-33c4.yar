rule TTP_XOR_WriteProcessMemory_33c4 {
  strings:
    $key_33c4 = { 64 b6 [2] 56 94 [2] 50 a1 [2] 7e a1 [2] 41 bd }

  condition:
    any of them
}