rule TTP_XOR_WriteProcessMemory_1203 {
  strings:
    $key_1203 = { 45 71 [2] 77 53 [2] 71 66 [2] 5f 66 [2] 60 7a }

  condition:
    any of them
}