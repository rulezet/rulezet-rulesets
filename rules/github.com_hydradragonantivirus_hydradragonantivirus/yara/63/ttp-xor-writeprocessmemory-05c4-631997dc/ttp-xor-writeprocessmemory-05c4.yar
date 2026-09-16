rule TTP_XOR_WriteProcessMemory_05c4 {
  strings:
    $key_05c4 = { 52 b6 [2] 60 94 [2] 66 a1 [2] 48 a1 [2] 77 bd }

  condition:
    any of them
}