rule TTP_XOR_WriteProcessMemory_31f6 {
  strings:
    $key_31f6 = { 66 84 [2] 54 a6 [2] 52 93 [2] 7c 93 [2] 43 8f }

  condition:
    any of them
}