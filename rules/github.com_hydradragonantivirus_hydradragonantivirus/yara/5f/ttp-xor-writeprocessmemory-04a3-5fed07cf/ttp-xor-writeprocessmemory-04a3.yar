rule TTP_XOR_WriteProcessMemory_04a3 {
  strings:
    $key_04a3 = { 53 d1 [2] 61 f3 [2] 67 c6 [2] 49 c6 [2] 76 da }

  condition:
    any of them
}