rule TTP_XOR_WriteProcessMemory_6bf7 {
  strings:
    $key_6bf7 = { 3c 85 [2] 0e a7 [2] 08 92 [2] 26 92 [2] 19 8e }

  condition:
    any of them
}