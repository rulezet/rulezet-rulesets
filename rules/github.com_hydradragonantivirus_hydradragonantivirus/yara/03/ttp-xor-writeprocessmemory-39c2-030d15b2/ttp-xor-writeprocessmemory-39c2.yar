rule TTP_XOR_WriteProcessMemory_39c2 {
  strings:
    $key_39c2 = { 6e b0 [2] 5c 92 [2] 5a a7 [2] 74 a7 [2] 4b bb }

  condition:
    any of them
}