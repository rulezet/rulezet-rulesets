rule TTP_XOR_WriteProcessMemory_3cf7 {
  strings:
    $key_3cf7 = { 6b 85 [2] 59 a7 [2] 5f 92 [2] 71 92 [2] 4e 8e }

  condition:
    any of them
}