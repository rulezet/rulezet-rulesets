rule TTP_XOR_WriteProcessMemory_19e7 {
  strings:
    $key_19e7 = { 4e 95 [2] 7c b7 [2] 7a 82 [2] 54 82 [2] 6b 9e }

  condition:
    any of them
}