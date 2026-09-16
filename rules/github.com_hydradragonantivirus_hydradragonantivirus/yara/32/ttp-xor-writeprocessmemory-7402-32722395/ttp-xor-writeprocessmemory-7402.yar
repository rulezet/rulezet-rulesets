rule TTP_XOR_WriteProcessMemory_7402 {
  strings:
    $key_7402 = { 23 70 [2] 11 52 [2] 17 67 [2] 39 67 [2] 06 7b }

  condition:
    any of them
}