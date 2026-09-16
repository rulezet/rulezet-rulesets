rule TTP_XOR_WriteProcessMemory_1403 {
  strings:
    $key_1403 = { 43 71 [2] 71 53 [2] 77 66 [2] 59 66 [2] 66 7a }

  condition:
    any of them
}