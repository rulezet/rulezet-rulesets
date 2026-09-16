rule TTP_XOR_WriteProcessMemory_0df7 {
  strings:
    $key_0df7 = { 5a 85 [2] 68 a7 [2] 6e 92 [2] 40 92 [2] 7f 8e }

  condition:
    any of them
}