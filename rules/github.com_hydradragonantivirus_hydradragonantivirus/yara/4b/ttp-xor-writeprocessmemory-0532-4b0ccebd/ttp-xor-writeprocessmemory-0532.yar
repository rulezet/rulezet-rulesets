rule TTP_XOR_WriteProcessMemory_0532 {
  strings:
    $key_0532 = { 52 40 [2] 60 62 [2] 66 57 [2] 48 57 [2] 77 4b }

  condition:
    any of them
}