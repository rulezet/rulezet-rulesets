rule TTP_XOR_WriteProcessMemory_33b9 {
  strings:
    $key_33b9 = { 64 cb [2] 56 e9 [2] 50 dc [2] 7e dc [2] 41 c0 }

  condition:
    any of them
}