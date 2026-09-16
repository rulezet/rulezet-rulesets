rule TTP_XOR_WriteProcessMemory_01e7 {
  strings:
    $key_01e7 = { 56 95 [2] 64 b7 [2] 62 82 [2] 4c 82 [2] 73 9e }

  condition:
    any of them
}