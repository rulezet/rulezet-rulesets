rule TTP_XOR_WriteProcessMemory_09e7 {
  strings:
    $key_09e7 = { 5e 95 [2] 6c b7 [2] 6a 82 [2] 44 82 [2] 7b 9e }

  condition:
    any of them
}