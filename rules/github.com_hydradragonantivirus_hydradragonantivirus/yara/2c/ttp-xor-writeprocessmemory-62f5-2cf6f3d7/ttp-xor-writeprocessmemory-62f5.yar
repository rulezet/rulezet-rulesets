rule TTP_XOR_WriteProcessMemory_62f5 {
  strings:
    $key_62f5 = { 35 87 [2] 07 a5 [2] 01 90 [2] 2f 90 [2] 10 8c }

  condition:
    any of them
}