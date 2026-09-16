rule TTP_XOR_WriteProcessMemory_7dc4 {
  strings:
    $key_7dc4 = { 2a b6 [2] 18 94 [2] 1e a1 [2] 30 a1 [2] 0f bd }

  condition:
    any of them
}