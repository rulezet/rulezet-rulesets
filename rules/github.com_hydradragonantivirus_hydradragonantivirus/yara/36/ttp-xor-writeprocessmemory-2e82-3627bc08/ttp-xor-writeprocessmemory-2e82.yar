rule TTP_XOR_WriteProcessMemory_2e82 {
  strings:
    $key_2e82 = { 79 f0 [2] 4b d2 [2] 4d e7 [2] 63 e7 [2] 5c fb }

  condition:
    any of them
}