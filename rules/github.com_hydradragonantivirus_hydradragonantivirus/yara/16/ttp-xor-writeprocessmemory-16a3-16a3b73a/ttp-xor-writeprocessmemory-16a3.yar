rule TTP_XOR_WriteProcessMemory_16a3 {
  strings:
    $key_16a3 = { 41 d1 [2] 73 f3 [2] 75 c6 [2] 5b c6 [2] 64 da }

  condition:
    any of them
}