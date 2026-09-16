rule TTP_XOR_WriteProcessMemory_0ecc {
  strings:
    $key_0ecc = { 59 be [2] 6b 9c [2] 6d a9 [2] 43 a9 [2] 7c b5 }

  condition:
    any of them
}