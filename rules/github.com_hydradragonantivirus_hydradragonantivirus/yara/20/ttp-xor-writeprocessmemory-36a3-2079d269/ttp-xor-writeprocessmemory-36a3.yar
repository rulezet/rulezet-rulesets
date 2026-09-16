rule TTP_XOR_WriteProcessMemory_36a3 {
  strings:
    $key_36a3 = { 61 d1 [2] 53 f3 [2] 55 c6 [2] 7b c6 [2] 44 da }

  condition:
    any of them
}