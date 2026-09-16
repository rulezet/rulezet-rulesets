rule TTP_XOR_WriteProcessMemory_04d5 {
  strings:
    $key_04d5 = { 53 a7 [2] 61 85 [2] 67 b0 [2] 49 b0 [2] 76 ac }

  condition:
    any of them
}