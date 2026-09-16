rule TTP_XOR_WriteProcessMemory_7bc6 {
  strings:
    $key_7bc6 = { 2c b4 [2] 1e 96 [2] 18 a3 [2] 36 a3 [2] 09 bf }

  condition:
    any of them
}