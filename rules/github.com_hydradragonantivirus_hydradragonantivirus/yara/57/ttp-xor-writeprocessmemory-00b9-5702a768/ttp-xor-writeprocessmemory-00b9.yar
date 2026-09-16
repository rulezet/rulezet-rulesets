rule TTP_XOR_WriteProcessMemory_00b9 {
  strings:
    $key_00b9 = { 57 cb [2] 65 e9 [2] 63 dc [2] 4d dc [2] 72 c0 }

  condition:
    any of them
}