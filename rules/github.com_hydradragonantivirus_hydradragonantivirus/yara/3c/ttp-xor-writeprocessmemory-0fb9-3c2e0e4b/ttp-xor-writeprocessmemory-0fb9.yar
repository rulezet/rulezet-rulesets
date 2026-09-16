rule TTP_XOR_WriteProcessMemory_0fb9 {
  strings:
    $key_0fb9 = { 58 cb [2] 6a e9 [2] 6c dc [2] 42 dc [2] 7d c0 }

  condition:
    any of them
}