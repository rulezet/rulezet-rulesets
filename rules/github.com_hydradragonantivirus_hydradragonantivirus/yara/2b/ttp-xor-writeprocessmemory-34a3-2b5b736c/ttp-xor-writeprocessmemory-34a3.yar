rule TTP_XOR_WriteProcessMemory_34a3 {
  strings:
    $key_34a3 = { 63 d1 [2] 51 f3 [2] 57 c6 [2] 79 c6 [2] 46 da }

  condition:
    any of them
}