rule TTP_XOR_WriteProcessMemory_39d5 {
  strings:
    $key_39d5 = { 6e a7 [2] 5c 85 [2] 5a b0 [2] 74 b0 [2] 4b ac }

  condition:
    any of them
}