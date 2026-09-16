rule TTP_XOR_WriteProcessMemory_2ac4 {
  strings:
    $key_2ac4 = { 7d b6 [2] 4f 94 [2] 49 a1 [2] 67 a1 [2] 58 bd }

  condition:
    any of them
}