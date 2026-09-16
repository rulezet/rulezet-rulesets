rule TTP_XOR_WriteProcessMemory_05e7 {
  strings:
    $key_05e7 = { 52 95 [2] 60 b7 [2] 66 82 [2] 48 82 [2] 77 9e }

  condition:
    any of them
}