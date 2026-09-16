rule TTP_XOR_WriteProcessMemory_0e82 {
  strings:
    $key_0e82 = { 59 f0 [2] 6b d2 [2] 6d e7 [2] 43 e7 [2] 7c fb }

  condition:
    any of them
}