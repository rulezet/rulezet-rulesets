rule TTP_XOR_WriteProcessMemory_1ecc {
  strings:
    $key_1ecc = { 49 be [2] 7b 9c [2] 7d a9 [2] 53 a9 [2] 6c b5 }

  condition:
    any of them
}