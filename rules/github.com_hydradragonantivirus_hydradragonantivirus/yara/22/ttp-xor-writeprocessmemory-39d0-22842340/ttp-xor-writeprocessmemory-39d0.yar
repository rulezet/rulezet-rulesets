rule TTP_XOR_WriteProcessMemory_39d0 {
  strings:
    $key_39d0 = { 6e a2 [2] 5c 80 [2] 5a b5 [2] 74 b5 [2] 4b a9 }

  condition:
    any of them
}