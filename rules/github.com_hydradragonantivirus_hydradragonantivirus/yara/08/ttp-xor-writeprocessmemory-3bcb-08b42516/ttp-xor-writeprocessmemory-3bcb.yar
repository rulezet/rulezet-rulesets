rule TTP_XOR_WriteProcessMemory_3bcb {
  strings:
    $key_3bcb = { 6c b9 [2] 5e 9b [2] 58 ae [2] 76 ae [2] 49 b2 }

  condition:
    any of them
}