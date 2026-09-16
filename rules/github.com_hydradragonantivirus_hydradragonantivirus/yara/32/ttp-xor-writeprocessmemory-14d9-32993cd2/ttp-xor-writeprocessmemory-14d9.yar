rule TTP_XOR_WriteProcessMemory_14d9 {
  strings:
    $key_14d9 = { 43 ab [2] 71 89 [2] 77 bc [2] 59 bc [2] 66 a0 }

  condition:
    any of them
}