rule TTP_XOR_WriteProcessMemory_05a3 {
  strings:
    $key_05a3 = { 52 d1 [2] 60 f3 [2] 66 c6 [2] 48 c6 [2] 77 da }

  condition:
    any of them
}