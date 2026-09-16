rule TTP_XOR_WriteProcessMemory_5d04 {
  strings:
    $key_5d04 = { 0a 76 [2] 38 54 [2] 3e 61 [2] 10 61 [2] 2f 7d }

  condition:
    any of them
}