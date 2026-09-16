rule TTP_XOR_WriteProcessMemory_2fb9 {
  strings:
    $key_2fb9 = { 78 cb [2] 4a e9 [2] 4c dc [2] 62 dc [2] 5d c0 }

  condition:
    any of them
}