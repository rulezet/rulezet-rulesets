rule TTP_XOR_WriteProcessMemory_5bcb {
  strings:
    $key_5bcb = { 0c b9 [2] 3e 9b [2] 38 ae [2] 16 ae [2] 29 b2 }

  condition:
    any of them
}