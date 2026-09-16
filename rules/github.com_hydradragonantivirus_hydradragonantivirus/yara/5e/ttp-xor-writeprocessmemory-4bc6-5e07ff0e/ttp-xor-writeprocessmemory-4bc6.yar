rule TTP_XOR_WriteProcessMemory_4bc6 {
  strings:
    $key_4bc6 = { 1c b4 [2] 2e 96 [2] 28 a3 [2] 06 a3 [2] 39 bf }

  condition:
    any of them
}