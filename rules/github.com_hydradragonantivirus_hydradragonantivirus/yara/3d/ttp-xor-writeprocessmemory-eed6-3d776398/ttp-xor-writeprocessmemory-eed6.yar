rule TTP_XOR_WriteProcessMemory_eed6 {
  strings:
    $key_eed6 = { b9 a4 [2] 8b 86 [2] 8d b3 [2] a3 b3 [2] 9c af }

  condition:
    any of them
}