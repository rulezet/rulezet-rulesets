rule TTP_XOR_WriteProcessMemory_0497 {
  strings:
    $key_0497 = { 53 e5 [2] 61 c7 [2] 67 f2 [2] 49 f2 [2] 76 ee }

  condition:
    any of them
}