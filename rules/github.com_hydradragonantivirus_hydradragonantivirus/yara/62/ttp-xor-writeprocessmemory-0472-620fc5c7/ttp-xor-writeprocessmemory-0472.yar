rule TTP_XOR_WriteProcessMemory_0472 {
  strings:
    $key_0472 = { 53 00 [2] 61 22 [2] 67 17 [2] 49 17 [2] 76 0b }

  condition:
    any of them
}