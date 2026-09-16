rule TTP_XOR_WriteProcessMemory_24e7 {
  strings:
    $key_24e7 = { 73 95 [2] 41 b7 [2] 47 82 [2] 69 82 [2] 56 9e }

  condition:
    any of them
}