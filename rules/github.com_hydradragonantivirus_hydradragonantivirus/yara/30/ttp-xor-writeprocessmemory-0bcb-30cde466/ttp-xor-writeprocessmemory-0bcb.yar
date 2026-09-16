rule TTP_XOR_WriteProcessMemory_0bcb {
  strings:
    $key_0bcb = { 5c b9 [2] 6e 9b [2] 68 ae [2] 46 ae [2] 79 b2 }

  condition:
    any of them
}