rule TTP_XOR_WriteProcessMemory_6ecc {
  strings:
    $key_6ecc = { 39 be [2] 0b 9c [2] 0d a9 [2] 23 a9 [2] 1c b5 }

  condition:
    any of them
}