rule TTP_XOR_WriteProcessMemory_39d1 {
  strings:
    $key_39d1 = { 6e a3 [2] 5c 81 [2] 5a b4 [2] 74 b4 [2] 4b a8 }

  condition:
    any of them
}