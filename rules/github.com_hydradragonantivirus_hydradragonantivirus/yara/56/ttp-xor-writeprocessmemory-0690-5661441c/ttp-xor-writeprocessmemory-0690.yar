rule TTP_XOR_WriteProcessMemory_0690 {
  strings:
    $key_0690 = { 51 e2 [2] 63 c0 [2] 65 f5 [2] 4b f5 [2] 74 e9 }

  condition:
    any of them
}