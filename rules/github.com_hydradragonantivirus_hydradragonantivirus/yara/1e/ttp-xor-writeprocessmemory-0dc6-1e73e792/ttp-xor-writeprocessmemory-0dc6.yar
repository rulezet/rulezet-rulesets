rule TTP_XOR_WriteProcessMemory_0dc6 {
  strings:
    $key_0dc6 = { 5a b4 [2] 68 96 [2] 6e a3 [2] 40 a3 [2] 7f bf }

  condition:
    any of them
}