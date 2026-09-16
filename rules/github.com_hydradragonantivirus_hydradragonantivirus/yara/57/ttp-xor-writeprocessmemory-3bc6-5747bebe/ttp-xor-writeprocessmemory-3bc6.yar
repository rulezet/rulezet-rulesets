rule TTP_XOR_WriteProcessMemory_3bc6 {
  strings:
    $key_3bc6 = { 6c b4 [2] 5e 96 [2] 58 a3 [2] 76 a3 [2] 49 bf }

  condition:
    any of them
}