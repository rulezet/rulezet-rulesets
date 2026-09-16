rule TTP_XOR_WriteProcessMemory_3021 {
  strings:
    $key_3021 = { 67 53 [2] 55 71 [2] 53 44 [2] 7d 44 [2] 42 58 }

  condition:
    any of them
}