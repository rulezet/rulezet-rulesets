rule TTP_XOR_WriteProcessMemory_7737 {
  strings:
    $key_7737 = { 20 45 [2] 12 67 [2] 14 52 [2] 3a 52 [2] 05 4e }

  condition:
    any of them
}