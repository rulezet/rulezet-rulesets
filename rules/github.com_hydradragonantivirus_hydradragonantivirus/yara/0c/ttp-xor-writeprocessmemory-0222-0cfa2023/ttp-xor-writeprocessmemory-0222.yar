rule TTP_XOR_WriteProcessMemory_0222 {
  strings:
    $key_0222 = { 55 50 [2] 67 72 [2] 61 47 [2] 4f 47 [2] 70 5b }

  condition:
    any of them
}