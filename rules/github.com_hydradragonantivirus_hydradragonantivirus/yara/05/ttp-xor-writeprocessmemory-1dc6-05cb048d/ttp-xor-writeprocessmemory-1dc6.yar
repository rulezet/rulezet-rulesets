rule TTP_XOR_WriteProcessMemory_1dc6 {
  strings:
    $key_1dc6 = { 4a b4 [2] 78 96 [2] 7e a3 [2] 50 a3 [2] 6f bf }

  condition:
    any of them
}