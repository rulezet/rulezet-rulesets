rule TTP_XOR_WriteProcessMemory_5b02 {
  strings:
    $key_5b02 = { 0c 70 [2] 3e 52 [2] 38 67 [2] 16 67 [2] 29 7b }

  condition:
    any of them
}