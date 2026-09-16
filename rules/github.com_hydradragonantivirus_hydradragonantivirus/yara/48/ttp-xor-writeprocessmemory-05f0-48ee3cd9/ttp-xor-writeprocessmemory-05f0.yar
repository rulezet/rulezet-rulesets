rule TTP_XOR_WriteProcessMemory_05f0 {
  strings:
    $key_05f0 = { 52 82 [2] 60 a0 [2] 66 95 [2] 48 95 [2] 77 89 }

  condition:
    any of them
}