rule TTP_XOR_WriteProcessMemory_09c5 {
  strings:
    $key_09c5 = { 5e b7 [2] 6c 95 [2] 6a a0 [2] 44 a0 [2] 7b bc }

  condition:
    any of them
}