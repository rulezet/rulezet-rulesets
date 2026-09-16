rule TTP_XOR_WriteProcessMemory_7bc4 {
  strings:
    $key_7bc4 = { 2c b6 [2] 1e 94 [2] 18 a1 [2] 36 a1 [2] 09 bd }

  condition:
    any of them
}