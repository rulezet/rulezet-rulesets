rule TTP_XOR_WriteProcessMemory_90b9 {
  strings:
    $key_90b9 = { c7 cb [2] f5 e9 [2] f3 dc [2] dd dc [2] e2 c0 }

  condition:
    any of them
}