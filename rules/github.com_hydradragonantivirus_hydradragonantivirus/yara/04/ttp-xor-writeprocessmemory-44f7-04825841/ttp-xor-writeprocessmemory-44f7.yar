rule TTP_XOR_WriteProcessMemory_44f7 {
  strings:
    $key_44f7 = { 13 85 [2] 21 a7 [2] 27 92 [2] 09 92 [2] 36 8e }

  condition:
    any of them
}