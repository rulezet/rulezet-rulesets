rule TTP_XOR_WriteProcessMemory_62f3 {
  strings:
    $key_62f3 = { 35 81 [2] 07 a3 [2] 01 96 [2] 2f 96 [2] 10 8a }

  condition:
    any of them
}