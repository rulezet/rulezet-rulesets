rule TTP_XOR_WriteProcessMemory_1ac5 {
  strings:
    $key_1ac5 = { 4d b7 [2] 7f 95 [2] 79 a0 [2] 57 a0 [2] 68 bc }

  condition:
    any of them
}