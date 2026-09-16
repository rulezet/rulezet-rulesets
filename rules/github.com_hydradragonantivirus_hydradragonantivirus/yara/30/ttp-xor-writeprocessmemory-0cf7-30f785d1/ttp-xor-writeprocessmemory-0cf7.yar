rule TTP_XOR_WriteProcessMemory_0cf7 {
  strings:
    $key_0cf7 = { 5b 85 [2] 69 a7 [2] 6f 92 [2] 41 92 [2] 7e 8e }

  condition:
    any of them
}