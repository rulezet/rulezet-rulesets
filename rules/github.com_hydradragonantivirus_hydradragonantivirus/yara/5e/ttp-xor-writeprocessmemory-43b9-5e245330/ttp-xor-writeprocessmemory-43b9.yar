rule TTP_XOR_WriteProcessMemory_43b9 {
  strings:
    $key_43b9 = { 14 cb [2] 26 e9 [2] 20 dc [2] 0e dc [2] 31 c0 }

  condition:
    any of them
}