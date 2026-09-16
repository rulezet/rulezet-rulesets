rule TTP_XOR_WriteProcessMemory_32f7 {
  strings:
    $key_32f7 = { 65 85 [2] 57 a7 [2] 51 92 [2] 7f 92 [2] 40 8e }

  condition:
    any of them
}