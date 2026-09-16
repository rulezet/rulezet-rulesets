rule TTP_XOR_WriteProcessMemory_1421 {
  strings:
    $key_1421 = { 43 53 [2] 71 71 [2] 77 44 [2] 59 44 [2] 66 58 }

  condition:
    any of them
}