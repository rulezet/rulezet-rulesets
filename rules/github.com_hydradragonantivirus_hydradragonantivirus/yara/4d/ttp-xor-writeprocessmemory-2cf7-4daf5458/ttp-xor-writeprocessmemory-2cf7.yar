rule TTP_XOR_WriteProcessMemory_2cf7 {
  strings:
    $key_2cf7 = { 7b 85 [2] 49 a7 [2] 4f 92 [2] 61 92 [2] 5e 8e }

  condition:
    any of them
}