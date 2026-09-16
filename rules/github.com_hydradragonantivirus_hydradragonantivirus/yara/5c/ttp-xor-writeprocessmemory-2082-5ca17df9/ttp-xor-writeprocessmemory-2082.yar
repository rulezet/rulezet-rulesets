rule TTP_XOR_WriteProcessMemory_2082 {
  strings:
    $key_2082 = { 77 f0 [2] 45 d2 [2] 43 e7 [2] 6d e7 [2] 52 fb }

  condition:
    any of them
}