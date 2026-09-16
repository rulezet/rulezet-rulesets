rule TTP_XOR_WriteProcessMemory_70b9 {
  strings:
    $key_70b9 = { 27 cb [2] 15 e9 [2] 13 dc [2] 3d dc [2] 02 c0 }

  condition:
    any of them
}