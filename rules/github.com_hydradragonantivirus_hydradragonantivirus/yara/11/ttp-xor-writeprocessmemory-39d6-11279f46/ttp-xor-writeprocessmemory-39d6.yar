rule TTP_XOR_WriteProcessMemory_39d6 {
  strings:
    $key_39d6 = { 6e a4 [2] 5c 86 [2] 5a b3 [2] 74 b3 [2] 4b af }

  condition:
    any of them
}