rule TTP_XOR_WriteProcessMemory_7e82 {
  strings:
    $key_7e82 = { 29 f0 [2] 1b d2 [2] 1d e7 [2] 33 e7 [2] 0c fb }

  condition:
    any of them
}