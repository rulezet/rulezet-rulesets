rule TTP_XOR_WriteProcessMemory_0491 {
  strings:
    $key_0491 = { 53 e3 [2] 61 c1 [2] 67 f4 [2] 49 f4 [2] 76 e8 }

  condition:
    any of them
}