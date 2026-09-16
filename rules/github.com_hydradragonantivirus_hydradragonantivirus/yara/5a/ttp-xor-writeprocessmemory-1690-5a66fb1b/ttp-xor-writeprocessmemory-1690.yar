rule TTP_XOR_WriteProcessMemory_1690 {
  strings:
    $key_1690 = { 41 e2 [2] 73 c0 [2] 75 f5 [2] 5b f5 [2] 64 e9 }

  condition:
    any of them
}