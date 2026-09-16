rule TTP_XOR_WriteProcessMemory_5690 {
  strings:
    $key_5690 = { 01 e2 [2] 33 c0 [2] 35 f5 [2] 1b f5 [2] 24 e9 }

  condition:
    any of them
}