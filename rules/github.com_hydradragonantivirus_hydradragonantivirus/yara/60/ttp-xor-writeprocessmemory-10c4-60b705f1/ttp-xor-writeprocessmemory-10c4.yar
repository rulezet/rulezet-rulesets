rule TTP_XOR_WriteProcessMemory_10c4 {
  strings:
    $key_10c4 = { 47 b6 [2] 75 94 [2] 73 a1 [2] 5d a1 [2] 62 bd }

  condition:
    any of them
}