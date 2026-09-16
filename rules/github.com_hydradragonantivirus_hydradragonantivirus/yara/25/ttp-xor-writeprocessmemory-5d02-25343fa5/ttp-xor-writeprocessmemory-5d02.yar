rule TTP_XOR_WriteProcessMemory_5d02 {
  strings:
    $key_5d02 = { 0a 70 [2] 38 52 [2] 3e 67 [2] 10 67 [2] 2f 7b }

  condition:
    any of them
}