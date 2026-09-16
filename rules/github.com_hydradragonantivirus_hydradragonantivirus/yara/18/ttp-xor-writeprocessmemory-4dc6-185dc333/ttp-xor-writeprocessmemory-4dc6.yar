rule TTP_XOR_WriteProcessMemory_4dc6 {
  strings:
    $key_4dc6 = { 1a b4 [2] 28 96 [2] 2e a3 [2] 00 a3 [2] 3f bf }

  condition:
    any of them
}