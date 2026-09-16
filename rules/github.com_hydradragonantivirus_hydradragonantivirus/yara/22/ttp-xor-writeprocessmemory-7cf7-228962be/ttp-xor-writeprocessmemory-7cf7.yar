rule TTP_XOR_WriteProcessMemory_7cf7 {
  strings:
    $key_7cf7 = { 2b 85 [2] 19 a7 [2] 1f 92 [2] 31 92 [2] 0e 8e }

  condition:
    any of them
}