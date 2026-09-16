rule TTP_XOR_WriteProcessMemory_24f7 {
  strings:
    $key_24f7 = { 73 85 [2] 41 a7 [2] 47 92 [2] 69 92 [2] 56 8e }

  condition:
    any of them
}