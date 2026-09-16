rule TTP_XOR_WriteProcessMemory_5dc6 {
  strings:
    $key_5dc6 = { 0a b4 [2] 38 96 [2] 3e a3 [2] 10 a3 [2] 2f bf }

  condition:
    any of them
}