rule TTP_XOR_WriteProcessMemory_31f3 {
  strings:
    $key_31f3 = { 66 81 [2] 54 a3 [2] 52 96 [2] 7c 96 [2] 43 8a }

  condition:
    any of them
}