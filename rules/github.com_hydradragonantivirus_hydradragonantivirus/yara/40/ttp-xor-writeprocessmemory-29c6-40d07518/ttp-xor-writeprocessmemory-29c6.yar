rule TTP_XOR_WriteProcessMemory_29c6 {
  strings:
    $key_29c6 = { 7e b4 [2] 4c 96 [2] 4a a3 [2] 64 a3 [2] 5b bf }

  condition:
    any of them
}