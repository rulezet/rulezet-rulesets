rule TTP_XOR_WriteProcessMemory_4fb9 {
  strings:
    $key_4fb9 = { 18 cb [2] 2a e9 [2] 2c dc [2] 02 dc [2] 3d c0 }

  condition:
    any of them
}