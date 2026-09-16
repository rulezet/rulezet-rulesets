rule TTP_XOR_WriteProcessMemory_1437 {
  strings:
    $key_1437 = { 43 45 [2] 71 67 [2] 77 52 [2] 59 52 [2] 66 4e }

  condition:
    any of them
}