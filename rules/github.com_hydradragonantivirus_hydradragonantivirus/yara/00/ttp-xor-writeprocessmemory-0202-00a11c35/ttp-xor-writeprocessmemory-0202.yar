rule TTP_XOR_WriteProcessMemory_0202 {
  strings:
    $key_0202 = { 55 70 [2] 67 52 [2] 61 67 [2] 4f 67 [2] 70 7b }

  condition:
    any of them
}