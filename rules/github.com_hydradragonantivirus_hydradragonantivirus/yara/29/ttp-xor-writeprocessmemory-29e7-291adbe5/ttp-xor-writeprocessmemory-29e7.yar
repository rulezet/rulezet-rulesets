rule TTP_XOR_WriteProcessMemory_29e7 {
  strings:
    $key_29e7 = { 7e 95 [2] 4c b7 [2] 4a 82 [2] 64 82 [2] 5b 9e }

  condition:
    any of them
}