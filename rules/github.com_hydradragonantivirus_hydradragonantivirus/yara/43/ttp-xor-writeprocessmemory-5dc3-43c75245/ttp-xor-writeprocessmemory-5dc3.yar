rule TTP_XOR_WriteProcessMemory_5dc3 {
  strings:
    $key_5dc3 = { 0a b1 [2] 38 93 [2] 3e a6 [2] 10 a6 [2] 2f ba }

  condition:
    any of them
}