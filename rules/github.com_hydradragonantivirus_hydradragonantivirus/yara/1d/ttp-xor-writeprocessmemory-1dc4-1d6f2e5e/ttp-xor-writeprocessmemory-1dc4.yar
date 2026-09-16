rule TTP_XOR_WriteProcessMemory_1dc4 {
  strings:
    $key_1dc4 = { 4a b6 [2] 78 94 [2] 7e a1 [2] 50 a1 [2] 6f bd }

  condition:
    any of them
}