rule TTP_XOR_WriteProcessMemory_7dc6 {
  strings:
    $key_7dc6 = { 2a b4 [2] 18 96 [2] 1e a3 [2] 30 a3 [2] 0f bf }

  condition:
    any of them
}