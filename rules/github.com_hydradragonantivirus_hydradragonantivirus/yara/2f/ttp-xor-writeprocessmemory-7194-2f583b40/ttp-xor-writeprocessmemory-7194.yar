rule TTP_XOR_WriteProcessMemory_7194 {
  strings:
    $key_7194 = { 26 e6 [2] 14 c4 [2] 12 f1 [2] 3c f1 [2] 03 ed }

  condition:
    any of them
}