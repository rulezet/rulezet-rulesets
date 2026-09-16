rule TTP_XOR_WriteProcessMemory_eed5 {
  strings:
    $key_eed5 = { b9 a7 [2] 8b 85 [2] 8d b0 [2] a3 b0 [2] 9c ac }

  condition:
    any of them
}