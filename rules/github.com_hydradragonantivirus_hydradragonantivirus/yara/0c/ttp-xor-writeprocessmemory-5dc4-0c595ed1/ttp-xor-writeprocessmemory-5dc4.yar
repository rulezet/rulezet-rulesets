rule TTP_XOR_WriteProcessMemory_5dc4 {
  strings:
    $key_5dc4 = { 0a b6 [2] 38 94 [2] 3e a1 [2] 10 a1 [2] 2f bd }

  condition:
    any of them
}