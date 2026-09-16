rule TTP_XOR_WriteProcessMemory_05f3 {
  strings:
    $key_05f3 = { 52 81 [2] 60 a3 [2] 66 96 [2] 48 96 [2] 77 8a }

  condition:
    any of them
}