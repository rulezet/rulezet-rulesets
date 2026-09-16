rule TTP_XOR_WriteProcessMemory_7fb9 {
  strings:
    $key_7fb9 = { 28 cb [2] 1a e9 [2] 1c dc [2] 32 dc [2] 0d c0 }

  condition:
    any of them
}