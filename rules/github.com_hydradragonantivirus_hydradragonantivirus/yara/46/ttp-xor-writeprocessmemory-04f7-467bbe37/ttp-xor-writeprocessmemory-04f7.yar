rule TTP_XOR_WriteProcessMemory_04f7 {
  strings:
    $key_04f7 = { 53 85 [2] 61 a7 [2] 67 92 [2] 49 92 [2] 76 8e }

  condition:
    any of them
}