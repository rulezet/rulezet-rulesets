rule TTP_XOR_WriteProcessMemory_39e7 {
  strings:
    $key_39e7 = { 6e 95 [2] 5c b7 [2] 5a 82 [2] 74 82 [2] 4b 9e }

  condition:
    any of them
}