rule TTP_XOR_WriteProcessMemory_3637 {
  strings:
    $key_3637 = { 61 45 [2] 53 67 [2] 55 52 [2] 7b 52 [2] 44 4e }

  condition:
    any of them
}