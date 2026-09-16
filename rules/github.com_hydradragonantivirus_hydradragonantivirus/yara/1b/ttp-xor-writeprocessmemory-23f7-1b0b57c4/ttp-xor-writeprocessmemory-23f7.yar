rule TTP_XOR_WriteProcessMemory_23f7 {
  strings:
    $key_23f7 = { 74 85 [2] 46 a7 [2] 40 92 [2] 6e 92 [2] 51 8e }

  condition:
    any of them
}