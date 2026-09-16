rule TTP_XOR_WriteProcessMemory_06f7 {
  strings:
    $key_06f7 = { 51 85 [2] 63 a7 [2] 65 92 [2] 4b 92 [2] 74 8e }

  condition:
    any of them
}