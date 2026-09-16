rule TTP_XOR_WriteProcessMemory_14a3 {
  strings:
    $key_14a3 = { 43 d1 [2] 71 f3 [2] 77 c6 [2] 59 c6 [2] 66 da }

  condition:
    any of them
}