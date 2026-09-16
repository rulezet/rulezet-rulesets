rule TTP_XOR_WriteProcessMemory_4ecc {
  strings:
    $key_4ecc = { 19 be [2] 2b 9c [2] 2d a9 [2] 03 a9 [2] 3c b5 }

  condition:
    any of them
}