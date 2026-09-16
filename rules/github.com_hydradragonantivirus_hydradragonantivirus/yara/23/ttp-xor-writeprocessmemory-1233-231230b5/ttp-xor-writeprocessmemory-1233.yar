rule TTP_XOR_WriteProcessMemory_1233 {
  strings:
    $key_1233 = { 45 41 [2] 77 63 [2] 71 56 [2] 5f 56 [2] 60 4a }

  condition:
    any of them
}