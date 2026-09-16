rule TTP_XOR_WriteProcessMemory_09c6 {
  strings:
    $key_09c6 = { 5e b4 [2] 6c 96 [2] 6a a3 [2] 44 a3 [2] 7b bf }

  condition:
    any of them
}