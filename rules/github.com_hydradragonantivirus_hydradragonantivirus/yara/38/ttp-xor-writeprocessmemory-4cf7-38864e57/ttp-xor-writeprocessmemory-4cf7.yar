rule TTP_XOR_WriteProcessMemory_4cf7 {
  strings:
    $key_4cf7 = { 1b 85 [2] 29 a7 [2] 2f 92 [2] 01 92 [2] 3e 8e }

  condition:
    any of them
}