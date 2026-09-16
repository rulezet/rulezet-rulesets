rule TTP_XOR_WriteProcessMemory_39c0 {
  strings:
    $key_39c0 = { 6e b2 [2] 5c 90 [2] 5a a5 [2] 74 a5 [2] 4b b9 }

  condition:
    any of them
}