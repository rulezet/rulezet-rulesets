rule TTP_XOR_WriteProcessMemory_31b9 {
  strings:
    $key_31b9 = { 66 cb [2] 54 e9 [2] 52 dc [2] 7c dc [2] 43 c0 }

  condition:
    any of them
}