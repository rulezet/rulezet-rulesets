rule TTP_XOR_WriteProcessMemory_09c2 {
  strings:
    $key_09c2 = { 5e b0 [2] 6c 92 [2] 6a a7 [2] 44 a7 [2] 7b bb }

  condition:
    any of them
}