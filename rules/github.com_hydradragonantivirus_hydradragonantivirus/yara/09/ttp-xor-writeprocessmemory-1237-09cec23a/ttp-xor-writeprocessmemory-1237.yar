rule TTP_XOR_WriteProcessMemory_1237 {
  strings:
    $key_1237 = { 45 45 [2] 77 67 [2] 71 52 [2] 5f 52 [2] 60 4e }

  condition:
    any of them
}