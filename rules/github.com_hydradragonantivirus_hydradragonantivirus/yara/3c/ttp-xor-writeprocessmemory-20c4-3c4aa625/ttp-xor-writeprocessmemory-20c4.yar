rule TTP_XOR_WriteProcessMemory_20c4 {
  strings:
    $key_20c4 = { 77 b6 [2] 45 94 [2] 43 a1 [2] 6d a1 [2] 52 bd }

  condition:
    any of them
}