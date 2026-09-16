rule TTP_XOR_WriteProcessMemory_3cc6 {
  strings:
    $key_3cc6 = { 6b b4 [2] 59 96 [2] 5f a3 [2] 71 a3 [2] 4e bf }

  condition:
    any of them
}