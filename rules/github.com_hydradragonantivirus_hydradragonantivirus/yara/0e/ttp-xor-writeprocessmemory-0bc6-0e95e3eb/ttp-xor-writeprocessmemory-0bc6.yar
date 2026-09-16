rule TTP_XOR_WriteProcessMemory_0bc6 {
  strings:
    $key_0bc6 = { 5c b4 [2] 6e 96 [2] 68 a3 [2] 46 a3 [2] 79 bf }

  condition:
    any of them
}