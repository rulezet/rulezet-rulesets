rule TTP_XOR_WriteProcessMemory_2ce7 {
  strings:
    $key_2ce7 = { 7b 95 [2] 49 b7 [2] 4f 82 [2] 61 82 [2] 5e 9e }

  condition:
    any of them
}