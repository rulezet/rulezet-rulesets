rule TTP_XOR_WriteProcessMemory_2dc4 {
  strings:
    $key_2dc4 = { 7a b6 [2] 48 94 [2] 4e a1 [2] 60 a1 [2] 5f bd }

  condition:
    any of them
}