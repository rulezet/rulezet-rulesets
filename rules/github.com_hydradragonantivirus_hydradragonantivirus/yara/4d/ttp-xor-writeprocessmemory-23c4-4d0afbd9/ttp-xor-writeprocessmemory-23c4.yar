rule TTP_XOR_WriteProcessMemory_23c4 {
  strings:
    $key_23c4 = { 74 b6 [2] 46 94 [2] 40 a1 [2] 6e a1 [2] 51 bd }

  condition:
    any of them
}